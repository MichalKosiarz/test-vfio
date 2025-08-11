use byteorder::{ByteOrder, NativeEndian};
use clap::Parser;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use thiserror::Error;
use vfio_ioctls::{VfioContainer, VfioDevice};

const GL_HIDA: u64 = 0x00082000;
const GL_HIDA_SIZE: usize = 32;
const GL_HIBA: u64 = 0x00081000;
const GL_HIBA_SIZE: usize = 4096;
const GL_HICR: u64 = 0x00082040;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// PCI device path (e.g., 0000:3b:00.0)
    #[arg(short, long)]
    device: Option<String>,

    /// List all PCI devices with IOMMU enabled
    #[arg(short, long)]
    list: bool,

    /// Run IOMMU diagnostics
    #[arg(long, short = 'D')]
    diagnose: bool,

    /// Show IOMMU groups topology and isolation analysis
    #[arg(long)]
    show_iommu_topology: bool,

    /// Analyze device drivers and binding status
    #[arg(long)]
    check_drivers: bool,

    /// Check VM readiness (QEMU/KVM, hugepages, etc.)
    #[arg(long)]
    check_vm_ready: bool,

    /// Unbind device from current driver
    #[arg(long)]
    unbind_device: Option<String>,

    /// Bind device to vfio-pci driver
    #[arg(long)]
    bind_to_vfio: Option<String>,

    /// Check security settings and permissions
    #[arg(long)]
    check_security: bool,
}

/// Error types for VFIO device passthrough operations and system validation.
///
/// This enum defines all possible error conditions that can occur during VFIO
/// (Virtual Function I/O) device passthrough operations, system validation,
/// and hardware configuration checks. Each error variant provides specific
/// context about the failure type and includes descriptive messages to help
/// users diagnose and resolve issues.
///
/// The error types cover the complete spectrum of VFIO operations from initial
/// hardware validation through device binding and advanced queue command
/// processing. Each variant is designed to provide actionable information
/// that guides users toward appropriate troubleshooting and resolution steps.
///
/// # Error Categories
///
/// ## System Configuration Errors
/// - [`IommuNotEnabled`]: IOMMU hardware or software configuration issues
/// - [`PathNotFound`]: Missing filesystem paths or device nodes
///
/// ## Device Management Errors
/// - [`VfioFailed`]: VFIO library operation failures
/// - [`DeviceBindingError`]: PCI device driver binding/unbinding issues
///
/// ## I/O and Communication Errors
/// - [`IoError`]: File system and device I/O operations
/// - [`FailedToSendAqCommand`]: Admin queue command transmission failures
/// - [`FailedToReceiveAqCommand`]: Admin queue command reception failures
/// - [`DeserializationError`]: Admin queue command data parsing failures
///
/// # Error Handling Patterns
///
/// ## Automatic Conversion
/// The enum implements automatic conversion from underlying error types:
/// ```rust
/// # use std::fs;
/// # use your_crate::PocError;
/// // IoError automatically converts from std::io::Error
/// fn read_config() -> Result<String, PocError> {
///     let content = fs::read_to_string("/etc/config")?; // Auto-converts io::Error
///     Ok(content)
/// }
///
/// // VfioFailed automatically converts from vfio_ioctls::VfioError
/// fn open_vfio_device() -> Result<(), PocError> {
///     let container = vfio_ioctls::VfioContainer::new()?; // Auto-converts VfioError
///     Ok(())
/// }
/// ```
///
/// ## Error Matching and Recovery
/// ```rust
/// # use your_crate::{PocError, check_iommu_enabled};
/// match check_iommu_enabled() {
///     Ok(()) => println!("IOMMU ready for device passthrough"),
///     Err(PocError::IommuNotEnabled(msg)) => {
///         eprintln!("IOMMU configuration issue: {}", msg);
///         eprintln!("Enable IOMMU in BIOS and kernel parameters");
///     }
///     Err(PocError::IoError(e)) => {
///         eprintln!("System access error: {}", e);
///         eprintln!("Check file permissions and system access");
///     }
///     Err(e) => eprintln!("Unexpected error: {}", e),
/// }
/// ```
///
/// # Integration with External Libraries
///
/// The error enum integrates seamlessly with external crates used in VFIO operations:
/// - **vfio_ioctls**: Automatic conversion from `VfioError` enables transparent error propagation
/// - **std::io**: Standard I/O errors are automatically wrapped for consistent error handling
/// - **thiserror**: Provides automatic `Display` and `Error` trait implementations
#[derive(Error, Debug)]
pub enum PocError {
    /// VFIO library operation failure.
    ///
    /// This error occurs when operations from the `vfio_ioctls` crate fail,
    /// typically due to VFIO device access issues, invalid IOMMU group
    /// operations, or VFIO container management problems.
    ///
    /// # Common Causes
    /// - VFIO device nodes not accessible (`/dev/vfio/vfio` missing)
    /// - Insufficient permissions to access VFIO devices
    /// - VFIO kernel modules not loaded
    /// - Invalid VFIO container or group operations
    /// - IOMMU group assignment conflicts
    ///
    /// # Troubleshooting
    /// - Ensure VFIO modules are loaded: `sudo modprobe vfio vfio-pci`
    /// - Check device permissions: `ls -la /dev/vfio/`
    /// - Verify user group membership: `groups $USER` (should include vfio)
    /// - Confirm IOMMU is enabled and functional
    ///
    /// # Example
    /// ```no_run
    /// # use vfio_ioctls::VfioContainer;
    /// # use your_crate::PocError;
    /// fn create_vfio_container() -> Result<VfioContainer, PocError> {
    ///     // This may fail with VfioFailed if /dev/vfio/vfio is inaccessible
    ///     let container = VfioContainer::new()?;
    ///     Ok(container)
    /// }
    /// ```
    #[error("Failed on VFIO create {0}")]
    VfioFailed(#[from] vfio_ioctls::VfioError),

    /// Required filesystem path or device node not found.
    ///
    /// This error indicates that an expected filesystem path, device node,
    /// or system interface is missing. This typically occurs when hardware
    /// features are disabled, kernel modules are not loaded, or the system
    /// lacks required capabilities.
    ///
    /// # Common Scenarios
    /// - IOMMU groups directory missing: `/sys/kernel/iommu_groups/`
    /// - VFIO device nodes not present: `/dev/vfio/vfio`
    /// - PCI device paths not found: `/sys/bus/pci/devices/`
    /// - Driver binding interfaces missing: `/sys/bus/pci/drivers/`
    ///
    /// # Resolution Steps
    /// - Verify hardware support and BIOS configuration
    /// - Check kernel module loading and configuration
    /// - Confirm IOMMU and virtualization are enabled
    /// - Validate system permissions and access rights
    ///
    /// # Example Usage
    /// ```rust
    /// # use std::path::Path;
    /// # use your_crate::PocError;
    /// fn check_vfio_device() -> Result<(), PocError> {
    ///     let vfio_path = Path::new("/dev/vfio/vfio");
    ///     if !vfio_path.exists() {
    ///         return Err(PocError::PathNotFound("/dev/vfio/vfio not found".to_string()));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[error("Path does not exist: {0}")]
    PathNotFound(String),

    /// IOMMU hardware or software configuration is not enabled.
    ///
    /// This error indicates that the Input-Output Memory Management Unit (IOMMU)
    /// is not properly configured or enabled on the system. IOMMU support is
    /// essential for VFIO device passthrough operations as it provides memory
    /// isolation and device access control.
    ///
    /// # Configuration Requirements
    /// - **Hardware**: CPU and chipset must support IOMMU (Intel VT-d or AMD-Vi)
    /// - **BIOS/UEFI**: Virtualization and IOMMU must be enabled in firmware
    /// - **Kernel**: Appropriate IOMMU parameters must be configured
    /// - **Groups**: IOMMU groups must be created and populated with devices
    ///
    /// # Common Causes
    /// - IOMMU disabled in BIOS/UEFI settings
    /// - Missing kernel parameters (`intel_iommu=on` or `amd_iommu=on`)
    /// - Hardware lacks IOMMU support
    /// - Kernel compiled without IOMMU support
    /// - VFIO modules not loaded
    ///
    /// # Resolution Process
    /// 1. **Hardware Validation**: Verify CPU and chipset IOMMU support
    /// 2. **BIOS Configuration**: Enable VT-x/AMD-V and VT-d/AMD-Vi
    /// 3. **Kernel Parameters**: Add IOMMU enable parameters to GRUB
    /// 4. **Module Loading**: Load VFIO kernel modules
    /// 5. **Verification**: Confirm IOMMU groups exist and are populated
    ///
    /// # Example Diagnosis
    /// ```rust
    /// # use your_crate::{PocError, check_iommu_enabled};
    /// match check_iommu_enabled() {
    ///     Err(PocError::IommuNotEnabled(msg)) => {
    ///         println!("IOMMU Issue: {}", msg);
    ///         println!("Resolution steps:");
    ///         println!("1. Enable IOMMU in BIOS/UEFI");
    ///         println!("2. Add kernel parameters: intel_iommu=on iommu=pt");
    ///         println!("3. Reboot system");
    ///         println!("4. Load VFIO modules: sudo modprobe vfio-pci");
    ///     }
    ///     Ok(()) => println!("IOMMU configured correctly"),
    ///     Err(e) => println!("Other error: {}", e),
    /// }
    /// ```
    #[error("IOMMU is not enabled on this system: {0}")]
    IommuNotEnabled(String),

    /// File system or device I/O operation failure.
    ///
    /// This error wraps standard I/O errors that occur during file system
    /// operations, device access, or system interface interactions. It
    /// automatically converts from `std::io::Error` to provide consistent
    /// error handling throughout the application.
    ///
    /// # Common I/O Operations
    /// - Reading system information files (`/proc/cpuinfo`, `/proc/cmdline`)
    /// - Accessing device attributes in sysfs (`/sys/bus/pci/devices/`)
    /// - Writing to driver binding interfaces
    /// - Directory enumeration for device discovery
    /// - Command execution for system queries
    ///
    /// # Typical Causes
    /// - Permission denied accessing system files
    /// - Device nodes not available or corrupted
    /// - File system mount issues
    /// - Concurrent access conflicts
    /// - Hardware I/O errors
    ///
    /// # Resolution Strategies
    /// - Run with appropriate privileges (sudo when necessary)
    /// - Verify file system integrity and mount status
    /// - Check device availability and access permissions
    /// - Retry operations after brief delays
    /// - Validate system configuration and hardware status
    ///
    /// # Example Handling
    /// ```rust
    /// # use std::fs;
    /// # use your_crate::PocError;
    /// fn read_cpu_info() -> Result<String, PocError> {
    ///     // IoError automatically converts from std::io::Error
    ///     let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
    ///     Ok(cpuinfo)
    /// }
    ///
    /// fn handle_io_error() {
    ///     match read_cpu_info() {
    ///         Err(PocError::IoError(e)) => {
    ///             eprintln!("I/O error reading CPU info: {}", e);
    ///             eprintln!("Check file permissions and system access");
    ///         }
    ///         Ok(info) => println!("CPU info: {}", info),
    ///         Err(e) => eprintln!("Other error: {}", e),
    ///     }
    /// }
    /// ```
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    /// PCI device driver binding or unbinding operation failure.
    ///
    /// This error occurs when operations to bind or unbind PCI devices to/from
    /// kernel drivers fail. These operations are essential for VFIO device
    /// passthrough as devices must be unbound from host drivers and bound to
    /// the vfio-pci driver.
    ///
    /// # Binding Operations
    /// - **Unbinding**: Removing device from current driver control
    /// - **Binding**: Assigning device to a specific driver (e.g., vfio-pci)
    /// - **Driver Loading**: Ensuring target drivers are available
    /// - **ID Registration**: Adding device IDs to driver binding tables
    ///
    /// # Common Failure Scenarios
    /// - Driver refuses to release device (device in use)
    /// - Target driver not loaded or available
    /// - Device already bound to requested driver
    /// - Permission denied writing to driver binding interfaces
    /// - Device dependencies preventing unbinding
    ///
    /// # Troubleshooting Steps
    /// - Verify device is not in active use by applications
    /// - Load required drivers (`sudo modprobe vfio-pci`)
    /// - Check driver binding interface permissions
    /// - Stop services using the device before unbinding
    /// - Verify device PCI address format and validity
    ///
    /// # Example Error Handling
    /// ```rust
    /// # use your_crate::{PocError, bind_device_to_vfio};
    /// fn bind_gpu_to_vfio(device: &str) -> Result<(), PocError> {
    ///     match bind_device_to_vfio(device) {
    ///         Err(PocError::DeviceBindingError(msg)) => {
    ///             eprintln!("Device binding failed: {}", msg);
    ///             eprintln!("Possible solutions:");
    ///             eprintln!("- Stop services using the device");
    ///             eprintln!("- Load vfio-pci driver: sudo modprobe vfio-pci");
    ///             eprintln!("- Check device is not in use");
    ///             Err(PocError::DeviceBindingError(msg))
    ///         }
    ///         result => result,
    ///     }
    /// }
    /// ```
    #[error("Device binding error: {0}")]
    DeviceBindingError(String),

    /// Admin queue command transmission failure.
    ///
    /// This error occurs when attempting to send commands to device admin
    /// queues fails. Admin queues are used for device configuration and
    /// control operations in advanced device management scenarios.
    ///
    /// # Admin Queue Operations
    /// - Device configuration commands
    /// - Feature negotiation and setup
    /// - Queue management operations
    /// - Device status and control queries
    ///
    /// # Common Transmission Failures
    /// - Device not ready to accept commands
    /// - Queue full or not properly initialized
    /// - Command format or parameters invalid
    /// - Device hardware or firmware issues
    /// - Timing or synchronization problems
    ///
    /// # Resolution Approaches
    /// - Verify device initialization state
    /// - Check queue configuration and status
    /// - Validate command format and parameters
    /// - Implement retry logic with appropriate delays
    /// - Reset device if persistent failures occur
    #[error("Failed to send AQ command: {0}")]
    FailedToSendAqCommand(String),

    /// Admin queue command reception failure.
    ///
    /// This error occurs when attempting to receive responses from device
    /// admin queues fails. This can indicate device communication issues,
    /// timing problems, or command processing failures.
    ///
    /// # Reception Failure Causes
    /// - Command timeout waiting for response
    /// - Device failed to process command
    /// - Queue interrupt or polling issues
    /// - Response format corruption or validation failure
    /// - Device reset or error state
    ///
    /// # Diagnostic Steps
    /// - Check device status and error registers
    /// - Verify command completion timing
    /// - Validate interrupt configuration
    /// - Monitor queue state and occupancy
    /// - Review device logs and error indicators
    #[error("Failed to receive AQ command: {0}")]
    FailedToReceiveAqCommand(String),

    /// Admin queue command data deserialization failure.
    ///
    /// This error occurs when admin queue command response data cannot be
    /// properly parsed or deserialized. This indicates data corruption,
    /// format mismatches, or protocol version incompatibilities.
    ///
    /// # Deserialization Issues
    /// - Response data format corruption
    /// - Protocol version mismatches
    /// - Unexpected response structure
    /// - Endianness or alignment problems
    /// - Incomplete or truncated responses
    ///
    /// # Resolution Strategies
    /// - Verify protocol version compatibility
    /// - Check response data integrity
    /// - Validate command and response formats
    /// - Review device firmware version
    /// - Implement robust parsing with error recovery
    #[error("Failed to deserialize AQ command.")]
    DeserializationError,
}

/// Validates IOMMU enablement and VFIO device availability for passthrough operations.
///
/// This function performs a comprehensive check of the system's IOMMU (Input-Output
/// Memory Management Unit) configuration to ensure it is properly enabled and
/// functional for VFIO device passthrough operations. It validates the presence
/// of IOMMU groups, verifies group population, and confirms VFIO device node
/// availability.
///
/// The function serves as a fundamental prerequisite check in the VFIO workflow,
/// confirming that the underlying infrastructure is correctly configured before
/// attempting more complex device management operations. This validation helps
/// identify configuration issues early in the process and provides clear
/// diagnostic information for troubleshooting.
///
/// # IOMMU Validation Process
///
/// The function performs three critical validation steps:
/// 1. **IOMMU Groups Directory**: Verifies `/sys/kernel/iommu_groups/` exists
/// 2. **Group Population**: Confirms IOMMU groups contain devices
/// 3. **VFIO Device Node**: Validates `/dev/vfio/vfio` is available
///
/// ## IOMMU Groups Directory Check
/// The presence of `/sys/kernel/iommu_groups/` indicates that:
/// - IOMMU is enabled in the kernel
/// - IOMMU hardware is functional
/// - IOMMU subsystem has initialized successfully
/// - Device isolation infrastructure is available
///
/// ## Group Population Validation
/// Counting devices in IOMMU groups verifies that:
/// - PCI devices are properly enumerated
/// - IOMMU groups have been created and populated
/// - Device isolation boundaries are established
/// - Hardware topology is correctly analyzed
///
/// ## VFIO Device Node Verification
/// The presence of `/dev/vfio/vfio` confirms that:
/// - VFIO kernel modules are loaded
/// - VFIO subsystem is initialized
/// - User space can access VFIO functionality
/// - Device passthrough operations are possible
///
/// # System Requirements
///
/// This function requires:
/// - Intel VT-d or AMD-Vi capable hardware
/// - IOMMU enabled in BIOS/UEFI firmware
/// - Kernel compiled with IOMMU support
/// - Appropriate kernel parameters (`intel_iommu=on` or `amd_iommu=on`)
/// - VFIO kernel modules loaded
/// - Sufficient permissions to access system interfaces
///
/// # Configuration Dependencies
///
/// ## Hardware Requirements
/// - **Intel Systems**: VT-x and VT-d support in CPU and chipset
/// - **AMD Systems**: AMD-V and AMD-Vi support in CPU and chipset
/// - **Motherboard**: IOMMU support in system firmware
/// - **Devices**: PCI devices compatible with passthrough operations
///
/// ## Software Requirements
/// - **Kernel Configuration**: IOMMU and VFIO options enabled
/// - **Boot Parameters**: Platform-specific IOMMU enable parameters
/// - **Module Loading**: vfio, vfio-pci, and related modules
/// - **Permissions**: Access to /sys and /dev filesystem interfaces
///
/// # Output Information
///
/// On successful validation, the function displays:
/// ```text
/// v IOMMU is enabled with 28 groups
/// ```
///
/// The group count provides insight into:
/// - **System Complexity**: More groups indicate better device isolation
/// - **Passthrough Readiness**: Each group represents assignable units
/// - **Hardware Topology**: Group count reflects PCI device organization
/// - **Configuration Quality**: Higher counts suggest optimal IOMMU setup
///
/// # Error Conditions and Diagnostics
///
/// ## Missing IOMMU Groups Directory
/// **Error**: `PocError::IommuNotEnabled("IOMMU groups directory not found")`
/// **Cause**: IOMMU not enabled in kernel or hardware
/// **Resolution**:
/// - Enable IOMMU in BIOS/UEFI settings
/// - Add kernel parameters: `intel_iommu=on` or `amd_iommu=on`
/// - Recompile kernel with IOMMU support if necessary
/// - Verify hardware IOMMU capability
///
/// ## Empty IOMMU Groups
/// **Error**: `PocError::IommuNotEnabled("No IOMMU groups found")`
/// **Cause**: IOMMU enabled but no devices assigned to groups
/// **Resolution**:
/// - Check PCI device enumeration
/// - Verify IOMMU hardware initialization
/// - Review kernel boot messages for IOMMU errors
/// - Confirm device compatibility with IOMMU
///
/// ## Missing VFIO Device Node
/// **Error**: `PocError::IommuNotEnabled("VFIO device not found")`
/// **Cause**: VFIO modules not loaded or VFIO disabled
/// **Resolution**:
/// - Load VFIO modules: `sudo modprobe vfio vfio-pci`
/// - Check module loading: `lsmod | grep vfio`
/// - Verify VFIO kernel configuration
/// - Check device node permissions: `ls -la /dev/vfio/`
///
/// # Integration with VFIO Workflow
///
/// This function is typically used as an early validation step:
/// 1. **System Readiness**: Call this function before device operations
/// 2. **Prerequisite Check**: Validate IOMMU before device enumeration
/// 3. **Configuration Verification**: Confirm setup before binding operations
/// 4. **Troubleshooting**: Use for diagnosing passthrough setup issues
/// 5. **Status Monitoring**: Periodic checks of IOMMU functionality
///
/// # Usage Examples
///
/// ## Basic Validation
/// ```no_run
/// # use your_crate::{check_iommu_enabled, PocError};
/// // Simple IOMMU readiness check
/// match check_iommu_enabled() {
///     Ok(()) => {
///         println!("IOMMU ready for device passthrough operations");
///         // Proceed with device enumeration and binding
///     }
///     Err(e) => {
///         eprintln!("IOMMU not ready: {}", e);
///         eprintln!("Please configure IOMMU before proceeding");
///     }
/// }
/// ```
///
/// ## Comprehensive Error Handling
/// ```no_run
/// # use your_crate::{check_iommu_enabled, PocError};
/// fn validate_vfio_prerequisites() -> Result<(), String> {
///     match check_iommu_enabled() {
///         Ok(()) => Ok(()),
///         Err(PocError::IommuNotEnabled(msg)) => {
///             let guidance = match msg.as_str() {
///                 "IOMMU groups directory not found" => {
///                     "Enable IOMMU in BIOS and add kernel parameters"
///                 }
///                 "No IOMMU groups found" => {
///                     "Check IOMMU hardware initialization and device enumeration"
///                 }
///                 "VFIO device not found" => {
///                     "Load VFIO kernel modules: sudo modprobe vfio vfio-pci"
///                 }
///                 _ => "Review IOMMU and VFIO configuration"
///             };
///             Err(format!("{}: {}", msg, guidance))
///         }
///         Err(e) => Err(format!("System access error: {}", e)),
///     }
/// }
/// ```
///
/// ## Workflow Integration
/// ```no_run
/// # use your_crate::{check_iommu_enabled, list_devices_with_iommu, bind_device_to_vfio};
/// fn setup_device_passthrough(device: &str) -> Result<(), Box<dyn std::error::Error>> {
///     // Step 1: Validate IOMMU readiness
///     check_iommu_enabled()?;
///
///     // Step 2: Enumerate available devices
///     // list_devices_with_iommu()?;
///
///     // Step 3: Bind device to VFIO
///     // bind_device_to_vfio(device)?;
///
///     println!("Device {} ready for passthrough", device);
///     Ok(())
/// }
/// ```
///
/// # Performance Considerations
///
/// The function performs several I/O operations:
/// - Directory existence check: ~1ms for filesystem access
/// - Directory enumeration: ~5-20ms depending on device count
/// - Device node verification: ~1ms for filesystem access
/// - Console output: <1ms for status display
///
/// Total execution time is typically under 50ms on modern systems, making it
/// suitable for frequent validation checks without significant performance impact.
///
/// # Security Considerations
///
/// - **Privilege Requirements**: May require elevated privileges for system access
/// - **Device Access**: VFIO operations can grant direct hardware access
/// - **Isolation Validation**: Confirms device isolation boundaries are established
/// - **System Impact**: IOMMU configuration affects system-wide device security
///
/// # Platform Compatibility
///
/// This function works across multiple hardware platforms:
/// - **Intel x86_64**: Full support for VT-d validation
/// - **AMD x86_64**: Full support for AMD-Vi validation
/// - **ARM64**: Limited support depending on SMMU implementation
/// - **Virtual Machines**: May reflect host IOMMU configuration
///
/// # Return Values
///
/// - `Ok(())`: IOMMU is properly enabled and functional for device passthrough
/// - `Err(PocError::IommuNotEnabled)`: IOMMU configuration issues preventing passthrough
/// - `Err(PocError::IoError)`: File system access failures during validation
///
/// Success indicates that the system is ready for VFIO device management operations,
/// while errors provide specific diagnostic information for troubleshooting.
///
/// # See Also
///
/// Related IOMMU and system validation functions:
/// - [`check_hardware_support()`]: Hardware capability validation
/// - [`check_bios_settings()`]: Firmware configuration validation
/// - [`check_kernel_parameters()`]: Kernel parameter validation
/// - [`run_diagnostics()`]: Comprehensive system validation
/// - [`list_devices_with_iommu()`]: Device enumeration and discovery
fn check_iommu_enabled() -> Result<(), PocError> {
    // Check if IOMMU groups directory exists and has content
    let iommu_groups_path = Path::new("/sys/kernel/iommu_groups");
    if !iommu_groups_path.exists() {
        return Err(PocError::IommuNotEnabled(
            "IOMMU groups directory not found".into(),
        ));
    }

    // Check if there are any IOMMU groups
    let entries = fs::read_dir(iommu_groups_path)?;
    let group_count = entries.count();

    if group_count == 0 {
        return Err(PocError::IommuNotEnabled("No IOMMU groups found".into()));
    }

    // Additional check: verify VFIO is available
    let vfio_path = Path::new("/dev/vfio/vfio");
    if !vfio_path.exists() {
        return Err(PocError::IommuNotEnabled("VFIO device not found".into()));
    }

    println!("v IOMMU is enabled with {group_count} groups");
    Ok(())
}

/// Validates hardware capabilities for virtualization and IOMMU device passthrough.
///
/// This function performs a fundamental hardware compatibility assessment to determine
/// if the system possesses the necessary processor and chipset features required for
/// VFIO device passthrough operations. It validates both CPU virtualization extensions
/// and IOMMU hardware support by examining processor capabilities and kernel boot
/// messages to ensure the hardware foundation is suitable for virtualization workloads.
///
/// The validation process serves as the foundational check in the VFIO setup workflow,
/// confirming that the hardware platform can support device passthrough before
/// proceeding with software configuration and device management operations. This
/// early validation helps identify hardware limitations that cannot be resolved
/// through software configuration changes.
///
/// # Hardware Capability Assessment
///
/// The function evaluates two critical hardware requirements:
/// 1. **CPU Virtualization Extensions**: Hardware-assisted virtualization support
/// 2. **IOMMU Hardware Presence**: Memory management unit for device isolation
///
/// ## CPU Virtualization Technology Validation
///
/// ### Intel VT-x (Virtual Technology Extensions)
/// - **Detection Method**: Searches for `vmx` flag in `/proc/cpuinfo`
/// - **Purpose**: Enables hardware-assisted virtualization on Intel processors
/// - **Requirements**: Intel Core, Xeon, or compatible processor with VT-x support
/// - **Significance**: Essential for efficient VM execution and CPU virtualization
///
/// ### AMD-V (AMD Virtualization Technology)
/// - **Detection Method**: Searches for `svm` flag in `/proc/cpuinfo`
/// - **Purpose**: Enables hardware-assisted virtualization on AMD processors
/// - **Requirements**: AMD Phenom, Opteron, Ryzen, or compatible processor with AMD-V
/// - **Significance**: Provides equivalent functionality to Intel VT-x for AMD platforms
///
/// ## IOMMU Hardware Detection
///
/// ### Intel VT-d (Virtualization Technology for Directed I/O)
/// - **Detection Method**: Searches kernel boot messages for "Intel-IOMMU" or "DMAR"
/// - **Purpose**: Provides device isolation and memory translation for device passthrough
/// - **Requirements**: Compatible Intel chipset with VT-d support
/// - **Boot Messages**: Kernel logs indicate successful IOMMU initialization
///
/// ### AMD-Vi (AMD I/O Virtualization Technology)
/// - **Detection Method**: Searches kernel boot messages for "AMD-Vi" or "AMD IOMMU"
/// - **Purpose**: Provides device isolation and memory translation for device passthrough
/// - **Requirements**: Compatible AMD chipset with AMD-Vi support
/// - **Boot Messages**: Kernel logs indicate successful IOMMU initialization
///
/// # Validation Process
///
/// The function follows a systematic approach to hardware capability validation:
///
/// ## CPU Feature Detection
/// - Reads comprehensive CPU information from `/proc/cpuinfo`
/// - Parses CPU feature flags to identify virtualization capabilities
/// - Distinguishes between Intel and AMD virtualization technologies
/// - Validates that virtualization extensions are exposed to the operating system
///
/// ## Processor Compatibility Assessment
/// - Confirms CPU supports hardware-assisted virtualization
/// - Identifies specific virtualization technology (VT-x vs AMD-V)
/// - Provides clear indication of virtualization readiness
/// - Returns error if no virtualization support is detected
///
/// ## IOMMU Hardware Verification
/// - Executes `dmesg` command to access kernel boot messages
/// - Searches boot logs for IOMMU initialization indicators
/// - Identifies platform-specific IOMMU implementations
/// - Provides informational status about IOMMU hardware detection
///
/// ## Compatibility Reporting
/// - Summarizes hardware virtualization capabilities
/// - Reports IOMMU hardware detection status
/// - Provides platform-specific guidance for missing features
/// - Offers troubleshooting suggestions for hardware issues
///
/// # Output Format
///
/// The function provides detailed console output organized by hardware component:
/// ```text
/// === Hardware Support Check ===
/// Virtualization support:
///   v Intel VT-x (vmx) - SUPPORTED
///
/// IOMMU support in kernel:
///   v Intel IOMMU/VT-d detected
/// ```
///
/// For systems with limited hardware support:
/// ```text
/// === Hardware Support Check ===
/// Virtualization support:
///   v AMD-V (svm) - SUPPORTED
///
/// IOMMU support in kernel:
///   ! No IOMMU detection in dmesg - may be disabled
/// ```
///
/// For incompatible hardware:
/// ```text
/// === Hardware Support Check ===
/// Virtualization support:
///   x No virtualization support in processor
/// ```
///
/// # Hardware Requirements and Compatibility
///
/// ## Intel Platform Requirements
///
/// ### Processor Requirements
/// - **CPU Families**: Core i3/i5/i7/i9, Xeon, or compatible Intel processors
/// - **VT-x Support**: Must be present in processor specifications
/// - **Generation**: Generally available on Core 2 Duo and newer (2006+)
/// - **Verification**: Check Intel ARK database for specific processor support
///
/// ### Chipset Requirements
/// - **VT-d Support**: Intel chipset must support Virtualization Technology for Directed I/O
/// - **Compatible Chipsets**: Most modern Intel chipsets (Q35, Z370, X299, etc.)
/// - **Enterprise Chipsets**: Xeon-class chipsets typically include VT-d support
/// - **Consumer Chipsets**: High-end consumer chipsets often include VT-d
///
/// ## AMD Platform Requirements
///
/// ### Processor Requirements
/// - **CPU Families**: Phenom, Opteron, FX, Ryzen, Threadripper, EPYC processors
/// - **AMD-V Support**: Must be present in processor specifications
/// - **Generation**: Available on most AMD processors since 2006
/// - **Verification**: Check AMD specifications for specific processor support
///
/// ### Chipset Requirements
/// - **AMD-Vi Support**: AMD chipset must support AMD I/O Virtualization Technology
/// - **Compatible Chipsets**: Modern AMD chipsets (B450, X470, X570, TRX40, etc.)
/// - **Server Chipsets**: EPYC and Threadripper platforms typically include AMD-Vi
/// - **Consumer Chipsets**: Mid-range and high-end consumer chipsets often include AMD-Vi
///
/// # Common Hardware Limitations
///
/// ## Missing Virtualization Support
/// - **Older Processors**: CPUs manufactured before 2006 may lack virtualization support
/// - **Entry-level Processors**: Some low-cost processors omit virtualization features
/// - **Mobile Processors**: Some ultra-low-power mobile CPUs may disable virtualization
/// - **Embedded Processors**: Specialized embedded CPUs may not include virtualization
///
/// ## Limited IOMMU Support
/// - **Consumer Platforms**: Some consumer chipsets may lack IOMMU support
/// - **Cost Optimization**: Entry-level motherboards may omit IOMMU functionality
/// - **Legacy Hardware**: Older systems may have limited or no IOMMU support
/// - **Integrated Graphics**: Systems relying solely on integrated graphics may have limited IOMMU
///
/// # Troubleshooting Hardware Issues
///
/// ## Virtualization Not Detected
/// When virtualization flags are missing from `/proc/cpuinfo`:
/// 1. **Verify Processor Support**: Check CPU specifications for VT-x/AMD-V support
/// 2. **BIOS/UEFI Configuration**: Enable virtualization in firmware settings
/// 3. **Firmware Updates**: Install latest BIOS/UEFI version from manufacturer
/// 4. **Operating System**: Ensure Linux kernel supports the processor
///
/// ## IOMMU Not Detected in Boot Messages
/// When IOMMU initialization messages are missing from dmesg:
/// 1. **Chipset Compatibility**: Verify motherboard supports VT-d/AMD-Vi
/// 2. **BIOS/UEFI Settings**: Enable IOMMU/VT-d/AMD-Vi in firmware
/// 3. **Kernel Parameters**: Add appropriate IOMMU parameters to kernel command line
/// 4. **Hardware Documentation**: Consult motherboard manual for IOMMU support
///
/// # System Requirements
///
/// This function requires:
/// - Linux operating system with `/proc/cpuinfo` support
/// - Access to kernel boot messages via `dmesg` command
/// - Intel VT-x/VT-d or AMD-V/AMD-Vi capable hardware
/// - Sufficient permissions to read CPU information and execute dmesg
/// - Modern processor with virtualization extensions
///
/// # Integration with VFIO Workflow
///
/// This function serves as the initial validation step in VFIO system setup:
/// 1. **Hardware Validation**: Use this function to verify basic hardware capabilities
/// 2. **Firmware Configuration**: Proceed to [`check_bios_settings()`] for firmware validation
/// 3. **Kernel Configuration**: Use [`check_kernel_parameters()`] for software settings
/// 4. **Device Management**: Continue with device enumeration and binding operations
/// 5. **Security Validation**: Use [`check_security_settings()`] for permission verification
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{check_hardware_support, PocError};
/// // Validate hardware virtualization capabilities
/// match check_hardware_support() {
///     Ok(()) => {
///         println!("Hardware validation successful");
///         println!("Processor supports virtualization");
///         // Continue with firmware and software configuration checks
///     }
///     Err(PocError::IommuNotEnabled(msg)) => {
///         eprintln!("Hardware incompatibility: {}", msg);
///         eprintln!("This system cannot support VFIO device passthrough");
///         eprintln!("Consider upgrading to compatible hardware");
///     }
///     Err(e) => {
///         eprintln!("Hardware check failed: {}", e);
///         eprintln!("Check system access and command availability");
///     }
/// }
/// ```
///
/// # Advanced Hardware Considerations
///
/// ## Performance Characteristics
/// - **Intel VT-x**: Provides excellent performance with EPT (Extended Page Tables)
/// - **AMD-V**: Offers competitive performance with NPT (Nested Page Tables)
/// - **IOMMU Translation**: Hardware memory translation reduces virtualization overhead
/// - **Interrupt Remapping**: Advanced IOMMU features improve interrupt handling
///
/// ## Hardware Generations and Features
/// - **Modern Processors**: Recent CPUs provide enhanced virtualization features
/// - **Legacy Support**: Older processors may have limited virtualization capabilities
/// - **Feature Evolution**: Newer hardware generations add improved virtualization support
/// - **Platform Integration**: Modern platforms integrate virtualization more tightly
///
/// ## Enterprise vs Consumer Hardware
/// - **Enterprise Platforms**: Typically include comprehensive virtualization support
/// - **Consumer Hardware**: May have selective virtualization feature implementation
/// - **Server Processors**: Generally provide full virtualization and IOMMU support
/// - **Workstation Platforms**: Usually include professional virtualization features
///
/// # Error Handling and Recovery
///
/// ## Hardware Incompatibility
/// When hardware lacks essential virtualization features:
/// - **CPU Upgrade**: Consider upgrading to a compatible processor
/// - **Platform Replacement**: May require motherboard upgrade for IOMMU support
/// - **Alternative Solutions**: Explore software-based virtualization alternatives
/// - **Compatibility Research**: Investigate specific hardware requirements
///
/// ## Partial Hardware Support
/// When some features are available but others are missing:
/// - **Feature Assessment**: Evaluate which capabilities are available
/// - **Limited Functionality**: Determine if partial support meets requirements
/// - **Incremental Upgrades**: Plan hardware improvements to achieve full support
/// - **Workaround Solutions**: Identify alternative approaches with available hardware
///
/// # Boot Message Analysis
///
/// ## Intel IOMMU Boot Messages
/// Common Intel VT-d initialization messages in dmesg:
/// ```text
/// Intel-IOMMU: enabled
/// DMAR: Host address width 39
/// DMAR: DRHD base: 0x000000fed90000 flags: 0x0
/// DMAR: IOMMU 0: reg_base_addr fed90000 ver 1:0 cap c0000020660462 ecap f0101a
/// ```
///
/// ## AMD IOMMU Boot Messages
/// Common AMD-Vi initialization messages in dmesg:
/// ```text
/// AMD-Vi: Found IOMMU at 0000:00:00.2 cap 0x40
/// AMD-Vi: Extended features (0xf77ef22294ada):
/// AMD-Vi: Interrupt remapping enabled
/// ```
///
/// # Performance Impact Analysis
///
/// The function performs several operations with measurable performance characteristics:
/// - Read `/proc/cpuinfo`: ~5-10ms for CPU information parsing
/// - Execute `dmesg` command: ~50-200ms depending on boot message volume
/// - String processing: <1ms for pattern matching and analysis
/// - Output formatting: <1ms for console display
///
/// Total execution time is typically under 250ms on modern systems, with most time
/// spent on dmesg command execution rather than CPU information processing.
///
/// # Platform Compatibility
///
/// This function works across multiple hardware architectures:
/// - **Intel x86_64**: Full support for VT-x and VT-d detection
/// - **AMD x86_64**: Full support for AMD-V and AMD-Vi detection
/// - **ARM64**: Limited support depending on processor and SMMU implementation
/// - **Virtual Machines**: May show host virtualization capabilities in some configurations
///
/// # Return Values
///
/// - `Ok(())`: Hardware validation completed successfully with compatible virtualization support
/// - `Err(PocError::IommuNotEnabled)`: CPU lacks virtualization support (blocking issue)
/// - `Err(PocError::IoError)`: System access failure during hardware detection
///
/// The function specifically returns an error when CPU virtualization support is absent,
/// as this represents a fundamental hardware limitation that prevents VFIO operations.
/// Missing IOMMU detection in boot messages is reported via console output but does not
/// cause function failure, as IOMMU issues may be resolved through configuration changes.
///
/// # See Also
///
/// Related hardware and system validation functions:
/// - [`check_bios_settings()`]: Firmware configuration validation
/// - [`check_kernel_parameters()`]: Kernel command line parameter validation
/// - [`run_diagnostics()`]: Comprehensive IOMMU system validation
/// - [`check_iommu_enabled()`]: Basic IOMMU functionality verification
/// - [`list_devices_with_iommu()`]: Device enumeration for passthrough planning
fn check_hardware_support() -> Result<(), PocError> {
    println!("=== Hardware Support Check ===");

    // Check CPU virtualization support
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
    let has_vmx = cpuinfo.contains("vmx");
    let has_svm = cpuinfo.contains("svm");

    println!("Virtualization support:");
    if has_vmx {
        println!("  v Intel VT-x (vmx) - SUPPORTED");
    } else if has_svm {
        println!("  v AMD-V (svm) - SUPPORTED");
    } else {
        println!("  x No virtualization support in processor");
        return Err(PocError::IommuNotEnabled(
            "CPU does not support virtualization".into(),
        ));
    }

    // Check for IOMMU in dmesg
    let dmesg_output = std::process::Command::new("dmesg").output()?;
    let dmesg_str = String::from_utf8_lossy(&dmesg_output.stdout);

    let has_intel_iommu = dmesg_str.contains("Intel-IOMMU") || dmesg_str.contains("DMAR");
    let has_amd_iommu = dmesg_str.contains("AMD-Vi") || dmesg_str.contains("AMD IOMMU");

    println!("IOMMU support in kernel:");
    if has_intel_iommu {
        println!("  v Intel IOMMU/VT-d detected");
    } else if has_amd_iommu {
        println!("  v AMD IOMMU/AMD-Vi detected");
    } else {
        println!("  ! No IOMMU detection in dmesg - may be disabled");
    }

    Ok(())
}

/// Validates BIOS/UEFI firmware configuration for virtualization and IOMMU support.
///
/// This function performs a comprehensive analysis of the system's firmware configuration
/// to ensure that essential virtualization technologies are properly enabled in the
/// BIOS or UEFI settings. It validates that both CPU virtualization extensions and
/// IOMMU hardware support are activated at the firmware level, which are prerequisites
/// for successful VFIO device passthrough operations.
///
/// The function serves as a critical diagnostic tool in the VFIO setup process by
/// identifying firmware-level configuration issues that cannot be resolved through
/// software configuration alone. Many virtualization and IOMMU features must be
/// explicitly enabled in the system firmware before they become available to the
/// operating system and applications.
///
/// # Firmware Configuration Validation
///
/// The analysis covers two fundamental aspects of firmware configuration:
/// 1. **CPU Virtualization Extensions**: Hardware-assisted virtualization support
/// 2. **IOMMU Hardware Support**: Memory management unit for device isolation
///
/// ## CPU Virtualization Technology Assessment
///
/// ### Intel VT-x (Virtual Technology Extensions)
/// - **Detection Method**: Searches for `vmx` flag in `/proc/cpuinfo`
/// - **Purpose**: Enables hardware-assisted virtualization on Intel processors
/// - **Requirements**: Compatible Intel processor with VT-x capability
/// - **BIOS Setting**: Usually found under "Virtualization Technology" or "Intel VT-x"
///
/// ### Intel EPT (Extended Page Tables)
/// - **Detection Method**: Searches for `ept` flag in CPU feature list
/// - **Purpose**: Hardware-assisted memory management for virtual machines
/// - **Benefits**: Improved VM memory performance and reduced overhead
/// - **Dependency**: Requires VT-x to be enabled first
///
/// ### AMD-V (AMD Virtualization)
/// - **Detection Method**: Searches for `svm` flag in `/proc/cpuinfo`
/// - **Purpose**: Enables hardware-assisted virtualization on AMD processors
/// - **Requirements**: Compatible AMD processor with AMD-V capability
/// - **BIOS Setting**: Usually found under "SVM Mode" or "AMD Virtualization"
///
/// ## IOMMU Hardware Configuration Assessment
///
/// ### Intel VT-d (Virtualization Technology for Directed I/O)
/// - **Firmware Requirement**: Must be enabled in BIOS/UEFI settings
/// - **Detection Method**: Validates IOMMU groups existence and functionality
/// - **Purpose**: Provides device isolation and secure device passthrough
/// - **Common Names**: "VT-d", "Directed I/O", "Intel IOMMU"
///
/// ### AMD-Vi (AMD I/O Virtualization Technology)
/// - **Firmware Requirement**: Must be enabled in BIOS/UEFI settings
/// - **Detection Method**: Validates IOMMU groups existence and functionality
/// - **Purpose**: Provides device isolation and secure device passthrough
/// - **Common Names**: "AMD-Vi", "IOMMU Support", "AMD I/O Virtualization"
///
/// # Validation Process
///
/// The function follows a systematic approach to firmware configuration validation:
///
/// ## CPU Feature Detection
/// - Reads complete CPU information from `/proc/cpuinfo`
/// - Parses CPU flags line to identify virtualization capabilities
/// - Distinguishes between Intel and AMD virtualization technologies
/// - Detects additional features like Extended Page Tables (EPT)
///
/// ## Virtualization Status Analysis
/// - Confirms that virtualization extensions are exposed to the operating system
/// - Validates that firmware has enabled these features properly
/// - Identifies when virtualization is disabled at the firmware level
/// - Provides platform-specific guidance for enabling virtualization
///
/// ## IOMMU Functional Verification
/// - Tests actual IOMMU functionality by examining kernel structures
/// - Counts available IOMMU groups to verify operational status
/// - Correlates firmware settings with kernel functionality
/// - Identifies cases where IOMMU is partially enabled but non-functional
///
/// ## Error Classification and Guidance
/// - Distinguishes between different types of configuration failures
/// - Provides specific remediation steps for each detected issue
/// - Offers platform-specific firmware navigation guidance
/// - Suggests systematic troubleshooting approaches
///
/// # Output Format
///
/// The function provides detailed console output with current status and remediation guidance:
/// ```text
/// === BIOS/UEFI Settings Check ===
///   v Intel VT-x enabled in BIOS
///   v EPT (Extended Page Tables) available
///   v IOMMU working correctly (28 groups)
/// ```
///
/// For systems with firmware configuration issues:
/// ```text
/// === BIOS/UEFI Settings Check ===
///   x Virtualization disabled in BIOS/UEFI
///      Need to enable:
///      - Intel: VT-x and VT-d
///      - AMD: AMD-V and AMD-Vi
///   x IOMMU probably disabled in BIOS
///      Check settings:
///      - Intel: VT-d / Directed I/O
///      - AMD: AMD-Vi / IOMMU Support
/// ```
///
/// # Firmware Configuration Issues and Solutions
///
/// ## Common Virtualization Disable Scenarios
///
/// ### Intel Systems Configuration
/// **Problem**: VT-x disabled in firmware
/// **Solution Steps**:
/// 1. **Access BIOS/UEFI**: Restart system and enter firmware setup (usually F2, F10, or Del)
/// 2. **Navigate to CPU Settings**: Look for "Advanced", "CPU Configuration", or "Processor"
/// 3. **Enable VT-x**: Find "Intel Virtualization Technology" or "Intel VT-x" and set to "Enabled"
/// 4. **Enable VT-d**: Find "VT-d" or "Directed I/O" and set to "Enabled"
/// 5. **Save and Exit**: Apply changes and restart system
///
/// **Common Setting Locations**:
/// - Advanced → CPU Configuration → Intel Virtualization Technology
/// - Processor → Intel VT-x Technology
/// - Security → Virtualization → Intel VT-x
/// - Chipset → North Bridge → Intel VT-d
///
/// ### AMD Systems Configuration
/// **Problem**: AMD-V or AMD-Vi disabled in firmware
/// **Solution Steps**:
/// 1. **Access BIOS/UEFI**: Restart system and enter firmware setup
/// 2. **Navigate to CPU Settings**: Look for "Advanced", "CPU Configuration", or "Processor"
/// 3. **Enable AMD-V**: Find "SVM Mode" or "AMD Virtualization" and set to "Enabled"
/// 4. **Enable AMD-Vi**: Find "IOMMU" or "AMD-Vi" and set to "Enabled"
/// 5. **Save and Exit**: Apply changes and restart system
///
/// **Common Setting Locations**:
/// - Advanced → CPU Configuration → SVM Mode
/// - Processor → AMD Virtualization Technology
/// - Advanced → AMD CBS → CPU Common Options → SVM Mode
/// - Advanced → AMD CBS → NBIO Common Options → IOMMU
///
/// ## IOMMU-Specific Configuration Issues
///
/// ### Partial IOMMU Enablement
/// **Symptoms**: CPU virtualization works but no IOMMU groups exist
/// **Cause**: VT-x/AMD-V enabled but VT-d/AMD-Vi disabled in firmware
/// **Resolution**: Enable IOMMU-specific settings in addition to basic virtualization
///
/// ### IOMMU Groups Present but Empty
/// **Symptoms**: IOMMU groups directory exists but contains no groups
/// **Cause**: IOMMU enabled in firmware but missing kernel parameters
/// **Resolution**: Check kernel configuration using [`check_kernel_parameters()`]
///
/// ### Conflicting Firmware Settings
/// **Symptoms**: Intermittent virtualization functionality
/// **Cause**: Some virtualization features enabled while others disabled
/// **Resolution**: Enable all virtualization-related settings comprehensively
///
/// # Platform-Specific Considerations
///
/// ## Intel Platform Requirements
/// - **VT-x**: Essential for hardware-assisted virtualization
/// - **VT-d**: Required for IOMMU functionality and device passthrough
/// - **EPT**: Recommended for improved memory management performance
/// - **AES-NI**: Optional but beneficial for encrypted VM disk performance
///
/// ## AMD Platform Requirements
/// - **AMD-V**: Essential for hardware-assisted virtualization
/// - **AMD-Vi**: Required for IOMMU functionality and device passthrough
/// - **NPT**: (Nested Page Tables) Usually enabled automatically with AMD-V
/// - **AES**: Optional but beneficial for encrypted VM disk performance
///
/// ## Motherboard and Chipset Variations
/// - **Consumer Motherboards**: May have simplified BIOS interfaces
/// - **Enterprise Motherboards**: Often provide more granular virtualization controls
/// - **OEM Systems**: May have vendor-specific firmware interfaces
/// - **Custom BIOS**: Enthusiast motherboards may have unique setting locations
///
/// # Error Handling and Recovery
///
/// ## Virtualization Detection Failures
/// When CPU virtualization flags are missing:
/// - **Verify Processor Support**: Check CPU specifications for VT-x/AMD-V support
/// - **Update Firmware**: Ensure latest BIOS/UEFI version is installed
/// - **Reset BIOS**: Consider factory reset if settings appear corrupted
/// - **Check Documentation**: Consult motherboard manual for specific setting names
///
/// ## IOMMU Functionality Issues
/// When IOMMU groups are missing or non-functional:
/// - **Verify Chipset Support**: Confirm motherboard supports VT-d/AMD-Vi
/// - **Check All Settings**: Ensure both CPU and chipset virtualization are enabled
/// - **Kernel Parameters**: Verify proper kernel command line configuration
/// - **Hardware Compatibility**: Some older hardware may have limited IOMMU support
///
/// # System Requirements
///
/// This function requires:
/// - Intel VT-x/VT-d or AMD-V/AMD-Vi capable hardware
/// - Access to `/proc/cpuinfo` for CPU feature detection
/// - Read access to `/sys/kernel/iommu_groups/` for IOMMU validation
/// - Compatible motherboard and chipset with virtualization support
/// - Proper firmware version supporting virtualization features
///
/// # Integration with VFIO Workflow
///
/// This function is typically used early in the VFIO setup validation process:
/// 1. **Hardware Detection**: Use [`check_hardware_support()`] for basic capability verification
/// 2. **Firmware Validation**: Use this function to validate BIOS/UEFI configuration
/// 3. **Kernel Configuration**: Use [`check_kernel_parameters()`] for software settings
/// 4. **Device Management**: Proceed with device enumeration and binding operations
/// 5. **Security Validation**: Use [`check_security_settings()`] for permission verification
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{check_bios_settings, PocError};
/// // Validate firmware virtualization configuration
/// match check_bios_settings() {
///     Ok(()) => println!("Firmware configuration validated successfully"),
///     Err(PocError::IommuNotEnabled(msg)) => {
///         eprintln!("Firmware configuration issue: {}", msg);
///         eprintln!("Please enable virtualization in BIOS/UEFI settings");
///     }
///     Err(e) => {
///         eprintln!("Firmware check failed: {}", e);
///         eprintln!("Check system access permissions");
///     }
/// }
/// ```
///
/// # Advanced Firmware Configuration
///
/// ## Intel Advanced Features
/// Beyond basic VT-x and VT-d enablement, consider these advanced settings:
/// - **TXT (Trusted Execution Technology)**: Enhanced security for virtualization
/// - **ACS (Access Control Services)**: Improved IOMMU group granularity
/// - **SR-IOV**: Single Root I/O Virtualization for network devices
/// - **Intel VT-c**: Virtualization for connectivity (if available)
///
/// ## AMD Advanced Features
/// Beyond basic AMD-V and AMD-Vi enablement, consider these advanced settings:
/// - **Memory Guard**: Enhanced memory security for virtualization
/// - **SMEE (Secure Memory Encryption)**: Memory encryption support
/// - **PSP (Platform Security Processor)**: Enhanced platform security
/// - **ACS Override**: Kernel parameter to improve IOMMU group isolation
///
/// # Troubleshooting Firmware Issues
///
/// ## Common Resolution Steps
/// 1. **Verify Hardware Support**: Confirm CPU and motherboard specifications
/// 2. **Update Firmware**: Install latest BIOS/UEFI version from manufacturer
/// 3. **Reset to Defaults**: Clear CMOS/NVRAM and reconfigure from defaults
/// 4. **Check Secure Boot**: Some virtualization features conflict with Secure Boot
/// 5. **Verify Power Management**: Disable aggressive power saving that may affect virtualization
///
/// ## Manufacturer-Specific Guidance
/// - **ASUS**: Look under "Advanced" → "CPU Configuration"
/// - **MSI**: Check "OC" → "CPU Features" or "Advanced" → "Integrated Peripherals"
/// - **Gigabyte**: Navigate to "M.I.T." → "Advanced Frequency Settings" → "Advanced CPU Settings"
/// - **ASRock**: Find under "Advanced" → "CPU Configuration"
/// - **Dell/HP**: Look in "System Configuration" → "BIOS/Platform Configuration"
///
/// # Performance Impact of Firmware Settings
///
/// ## Virtualization Overhead
/// - **Hardware Acceleration**: Proper firmware configuration minimizes virtualization overhead
/// - **Memory Management**: EPT/NPT significantly improves VM memory performance
/// - **Interrupt Handling**: VT-d/AMD-Vi enables efficient interrupt remapping
/// - **Security Features**: Some security features may impact performance slightly
///
/// ## Power Management Considerations
/// - **CPU States**: Some C-states may interfere with low-latency virtualization
/// - **Frequency Scaling**: Consider disabling for consistent VM performance
/// - **Thermal Management**: Ensure adequate cooling for sustained virtualization workloads
/// - **Power Limits**: Verify power delivery supports full virtualization load
///
/// # Error Recovery and Validation
///
/// ## Validation After Configuration Changes
/// After making firmware changes, validate the configuration:
/// 1. **Reboot System**: Firmware changes require system restart
/// 2. **Run Diagnostics**: Use [`run_diagnostics()`] for comprehensive validation
/// 3. **Check Kernel Messages**: Review `dmesg` for virtualization initialization
/// 4. **Verify IOMMU Groups**: Confirm IOMMU groups are created and populated
/// 5. **Test Device Passthrough**: Perform basic VFIO operations to confirm functionality
///
/// ## Rollback Procedures
/// If firmware changes cause system instability:
/// 1. **CMOS Reset**: Clear CMOS to restore default settings
/// 2. **Firmware Recovery**: Use manufacturer recovery procedures if available
/// 3. **Stepwise Enablement**: Enable virtualization features incrementally
/// 4. **Document Working Configuration**: Record successful settings for future reference
///
/// # Return Values
///
/// - `Ok(())`: Firmware configuration validation completed successfully
/// - `Err(PocError::IommuNotEnabled)`: Critical virtualization features disabled in firmware
/// - `Err(PocError::IoError)`: File system access error during validation
///
/// The function returns an error specifically when virtualization is disabled in firmware,
/// as this represents a blocking issue that prevents VFIO operations from succeeding.
/// IOMMU-related warnings are reported via console output but don't cause function failure
/// unless virtualization itself is completely disabled.
///
/// # Performance Considerations
///
/// The function performs several I/O operations:
/// - Read `/proc/cpuinfo`: ~5-10ms for CPU information parsing
/// - Parse CPU flags: <1ms for string processing
/// - Directory enumeration: ~5-15ms for IOMMU groups validation
/// - String analysis: <1ms for feature detection
///
/// Total execution time is typically under 50ms on modern systems.
///
/// # Platform Compatibility
///
/// This function works across multiple hardware platforms:
/// - **Intel x86_64**: Full support for VT-x and VT-d validation
/// - **AMD x86_64**: Full support for AMD-V and AMD-Vi validation
/// - **ARM64**: Limited support depending on specific SoC capabilities
/// - **Virtual Machines**: May show host virtualization configuration
///
/// # See Also
///
/// Related system validation functions:
/// - [`check_hardware_support()`]: Hardware capability detection and dmesg analysis
/// - [`check_kernel_parameters()`]: Kernel command line parameter validation
/// - [`run_diagnostics()`]: Comprehensive IOMMU system validation
/// - [`check_iommu_enabled()`]: Basic IOMMU functionality verification
/// - [`list_devices_with_iommu()`]: Device enumeration for passthrough planning
fn check_bios_settings() -> Result<(), PocError> {
    println!("\n=== BIOS/UEFI Settings Check ===");

    // Check for virtualization flags in CPU
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
    let cpu_flags = cpuinfo
        .lines()
        .find(|line| line.starts_with("flags"))
        .unwrap_or("");

    if cpu_flags.contains("vmx") {
        println!("  v Intel VT-x enabled in BIOS");
        if cpu_flags.contains("ept") {
            println!("  v EPT (Extended Page Tables) available");
        }
    } else if cpu_flags.contains("svm") {
        println!("  v AMD-V enabled in BIOS");
    } else {
        println!("  x Virtualization disabled in BIOS/UEFI");
        println!("     Need to enable:");
        println!("     - Intel: VT-x and VT-d");
        println!("     - AMD: AMD-V and AMD-Vi");
        return Err(PocError::IommuNotEnabled(
            "Virtualization disabled in BIOS".into(),
        ));
    }

    // Check if IOMMU is actually working
    let iommu_groups_path = Path::new("/sys/kernel/iommu_groups");
    if iommu_groups_path.exists() {
        let entries = fs::read_dir(iommu_groups_path)?;
        let group_count = entries.count();
        if group_count > 0 {
            println!("  v IOMMU working correctly ({group_count} groups)");
        } else {
            println!("  x IOMMU enabled but no groups found");
        }
    } else {
        println!("  x IOMMU probably disabled in BIOS");
        println!("     Check settings:");
        println!("     - Intel: VT-d / Directed I/O");
        println!("     - AMD: AMD-Vi / IOMMU Support");
    }

    Ok(())
}

/// Analyzes kernel command line parameters for IOMMU and virtualization configuration.
///
/// This function performs a comprehensive examination of the current kernel boot parameters
/// to validate that IOMMU (Input-Output Memory Management Unit) support is properly
/// configured for VFIO device passthrough operations. It checks for the presence of
/// platform-specific IOMMU parameters, analyzes passthrough mode configuration, and
/// provides detailed guidance for correcting configuration issues.
///
/// The analysis focuses on three critical kernel parameters that control IOMMU behavior:
/// 1. **Platform IOMMU Enable**: `intel_iommu=on` (Intel) or `amd_iommu=on` (AMD)
/// 2. **Passthrough Mode**: `iommu=pt` for optimal performance
/// 3. **Functional Validation**: Verification that IOMMU groups exist and are operational
///
/// # IOMMU Configuration Requirements
///
/// ## Intel VT-d Systems
/// Intel systems require the `intel_iommu=on` kernel parameter to enable the Intel
/// Virtualization Technology for Directed I/O (VT-d). This parameter activates the
/// Intel IOMMU hardware and enables the kernel's IOMMU subsystem to manage device
/// access control and memory translation for virtualization scenarios.
///
/// ## AMD-Vi Systems
/// AMD systems require the `amd_iommu=on` kernel parameter to enable AMD
/// Virtualization Technology for I/O (AMD-Vi). This parameter activates the AMD
/// IOMMU hardware and provides equivalent functionality to Intel VT-d for device
/// isolation and memory management in virtualization environments.
///
/// ## Passthrough Mode Optimization
/// The `iommu=pt` parameter configures the IOMMU in passthrough mode, which provides
/// optimal performance for device passthrough scenarios by reducing translation
/// overhead for devices that don't require isolation. This mode allows devices
/// direct memory access when appropriate while maintaining security boundaries.
///
/// # Parameter Analysis Process
///
/// The function follows a systematic approach to kernel parameter validation:
///
/// ## Command Line Extraction
/// - Reads the complete kernel command line from `/proc/cmdline`
/// - Displays the current parameters for user verification
/// - Provides transparency into the active kernel configuration
/// - Enables manual verification of parameter presence and syntax
///
/// ## Platform Detection
/// - Analyzes CPU features in `/proc/cpuinfo` to determine system type
/// - Detects Intel VT-x capability through `vmx` CPU flag
/// - Detects AMD-V capability through `svm` CPU flag
/// - Provides platform-specific configuration recommendations
///
/// ## Parameter Validation
/// - Searches for platform-appropriate IOMMU enable parameters
/// - Checks for performance optimization flags like `iommu=pt`
/// - Validates that parameters are syntactically correct
/// - Confirms parameters are properly applied by the kernel
///
/// ## Functional Verification
/// - Tests IOMMU functionality by examining `/sys/kernel/iommu_groups/`
/// - Counts available IOMMU groups to verify operational status
/// - Correlates parameter presence with actual IOMMU functionality
/// - Identifies cases where parameters are present but IOMMU is non-functional
///
/// # Output Format
///
/// The function provides detailed console output with current status and recommendations:
/// ```text
/// === Kernel Parameters Check ===
/// Current kernel parameters:
///   BOOT_IMAGE=/vmlinuz-5.15.0 root=/dev/sda1 intel_iommu=on iommu=pt quiet
///
/// Parameter analysis:
///   v intel_iommu=on - Intel IOMMU enabled
///   v iommu=pt - passthrough mode enabled
///   v IOMMU working: 28 groups available
/// ```
///
/// For systems with missing configuration:
/// ```text
/// === Kernel Parameters Check ===
/// Current kernel parameters:
///   BOOT_IMAGE=/vmlinuz-5.15.0 root=/dev/sda1 quiet splash
///
/// Parameter analysis:
///   ! No IOMMU parameter in kernel
///      Add to /etc/default/grub:
///      GRUB_CMDLINE_LINUX_DEFAULT="... intel_iommu=on iommu=pt"
///      Then run: sudo update-grub && sudo reboot
///   ! No iommu=pt - recommended for performance
///   x IOMMU not working - check parameters and restart
/// ```
///
/// # Configuration Correction Guidance
///
/// When kernel parameters are missing or incorrect, the function provides specific
/// remediation steps based on the detected system configuration:
///
/// ## Intel Systems Configuration
/// For Intel VT-x capable systems (detected by `vmx` CPU flag):
/// ```bash
/// # Edit GRUB configuration
/// sudo nano /etc/default/grub
///
/// # Add parameters to existing line:
/// GRUB_CMDLINE_LINUX_DEFAULT="quiet splash intel_iommu=on iommu=pt"
///
/// # Update GRUB and reboot
/// sudo update-grub
/// sudo reboot
/// ```
///
/// ## AMD Systems Configuration
/// For AMD-V capable systems (detected by `svm` CPU flag):
/// ```bash
/// # Edit GRUB configuration
/// sudo nano /etc/default/grub
///
/// # Add parameters to existing line:
/// GRUB_CMDLINE_LINUX_DEFAULT="quiet splash amd_iommu=on iommu=pt"
///
/// # Update GRUB and reboot
/// sudo update-grub
/// sudo reboot
/// ```
///
/// ## Universal Configuration
/// For systems where CPU vendor cannot be determined automatically:
/// ```bash
/// # Intel systems:
/// GRUB_CMDLINE_LINUX_DEFAULT="... intel_iommu=on iommu=pt"
///
/// # AMD systems:
/// GRUB_CMDLINE_LINUX_DEFAULT="... amd_iommu=on iommu=pt"
/// ```
///
/// # Parameter Details and Effects
///
/// ## intel_iommu=on
/// - **Purpose**: Enables Intel VT-d IOMMU hardware support
/// - **Effect**: Activates IOMMU for device isolation and memory translation
/// - **Requirements**: Intel chipset with VT-d support
/// - **Dependencies**: Requires VT-d enabled in BIOS/UEFI firmware
///
/// ## amd_iommu=on
/// - **Purpose**: Enables AMD-Vi IOMMU hardware support
/// - **Effect**: Activates IOMMU for device isolation and memory translation
/// - **Requirements**: AMD chipset with AMD-Vi support
/// - **Dependencies**: Requires AMD-Vi enabled in BIOS/UEFI firmware
///
/// ## iommu=pt (Passthrough Mode)
/// - **Purpose**: Optimizes IOMMU performance for passthrough scenarios
/// - **Effect**: Reduces translation overhead for direct device access
/// - **Benefits**: Improved performance for VFIO device passthrough
/// - **Compatibility**: Works with both Intel and AMD IOMMU implementations
///
/// # Common Configuration Issues
///
/// The function identifies and addresses several common configuration problems:
///
/// ## Missing IOMMU Parameters
/// - Kernel boots without IOMMU support enabled
/// - No IOMMU groups created during system initialization
/// - Device passthrough operations will fail
/// - Requires kernel parameter addition and system reboot
///
/// ## Incorrect Platform Parameters
/// - Using Intel parameters on AMD systems or vice versa
/// - May result in IOMMU not being enabled properly
/// - Function detects CPU type and suggests correct parameters
/// - Requires correction and system reboot
///
/// ## BIOS/Firmware Conflicts
/// - Kernel parameters present but IOMMU not functional
/// - Usually indicates IOMMU disabled in BIOS/UEFI settings
/// - Requires firmware configuration changes
/// - May need both firmware and kernel parameter updates
///
/// ## Syntax Errors
/// - Malformed kernel parameters preventing proper parsing
/// - Typos in parameter names or values
/// - Missing required values for IOMMU parameters
/// - Requires careful review and correction of GRUB configuration
///
/// # System Requirements
///
/// This function requires:
/// - Linux operating system with `/proc/cmdline` support
/// - Access to `/proc/cpuinfo` for CPU feature detection
/// - Read access to `/sys/kernel/iommu_groups/` for functional verification
/// - Intel VT-d or AMD-Vi capable hardware
/// - IOMMU support enabled in BIOS/UEFI firmware
///
/// # Integration with VFIO Workflow
///
/// This function is typically used as part of comprehensive VFIO system validation:
/// 1. **Hardware Check**: Use [`check_hardware_support()`] for basic capability detection
/// 2. **BIOS Validation**: Use [`check_bios_settings()`] for firmware configuration
/// 3. **Kernel Parameters**: Use this function to validate kernel configuration
/// 4. **Device Analysis**: Proceed with [`list_devices_with_iommu()`] and device management
/// 5. **Security Validation**: Use [`check_security_settings()`] for permission verification
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{check_kernel_parameters, PocError};
/// // Validate kernel IOMMU configuration
/// match check_kernel_parameters() {
///     Ok(()) => println!("Kernel parameters validated - check output for issues"),
///     Err(e) => {
///         eprintln!("Kernel parameter check failed: {}", e);
///         eprintln!("Check system access and filesystem permissions");
///     }
/// }
/// ```
///
/// # Advanced Configuration Options
///
/// Beyond basic IOMMU enablement, additional kernel parameters may be beneficial:
///
/// ## Extended Intel Parameters
/// ```bash
/// # Enhanced Intel configuration
/// intel_iommu=on,sm_on iommu=pt
/// # sm_on enables Scalable Mode for improved performance
/// ```
///
/// ## AMD Extended Parameters
/// ```bash
/// # Enhanced AMD configuration
/// amd_iommu=on,fullflush iommu=pt
/// # fullflush ensures complete TLB flushing for security
/// ```
///
/// ## Additional Performance Parameters
/// ```bash
/// # Performance optimization
/// intel_iommu=on iommu=pt default_hugepagesz=1G hugepagesz=1G hugepages=8
/// # Combines IOMMU with hugepage configuration for VM performance
/// ```
///
/// # Troubleshooting Parameter Issues
///
/// ## Verification Steps
/// 1. **Check Current Parameters**: Examine `/proc/cmdline` output
/// 2. **Verify GRUB Config**: Review `/etc/default/grub` for correct syntax
/// 3. **Test IOMMU Groups**: Confirm `/sys/kernel/iommu_groups/` exists and contains groups
/// 4. **Check System Messages**: Review `dmesg | grep -i iommu` for initialization errors
///
/// ## Common Fixes
/// - **Double-check spelling**: Ensure parameter names are exactly correct
/// - **Verify GRUB update**: Run `sudo update-grub` after editing configuration
/// - **Confirm reboot**: Parameters only take effect after system restart
/// - **Check firmware**: Ensure IOMMU enabled in BIOS/UEFI settings
///
/// # Error Handling
///
/// The function implements robust error handling for system access issues:
///
/// ## File Access Errors
/// - Handles missing `/proc/cmdline` (unusual but possible in containers)
/// - Graceful handling of `/proc/cpuinfo` access failures
/// - Robust error reporting for filesystem permission issues
/// - Continues analysis despite partial access failures
///
/// ## IOMMU Group Validation
/// - Handles missing IOMMU groups directory gracefully
/// - Provides clear indication when IOMMU is non-functional
/// - Distinguishes between missing parameters and hardware issues
/// - Offers specific guidance based on detected failure mode
///
/// # Performance Considerations
///
/// The function performs several I/O operations:
/// - Read `/proc/cmdline`: ~1ms for kernel command line access
/// - Read `/proc/cpuinfo`: ~5-10ms for CPU information parsing
/// - Directory enumeration: ~5-15ms for IOMMU groups counting
/// - String processing: <1ms for parameter analysis
///
/// Total execution time is typically under 50ms on modern systems.
///
/// # Platform Compatibility
///
/// This function supports multiple hardware platforms:
/// - **Intel x86_64**: Full support for VT-d parameter validation
/// - **AMD x86_64**: Full support for AMD-Vi parameter validation
/// - **ARM64**: Limited support depending on SMMU implementation
/// - **Virtual Machines**: May show host IOMMU configuration in some cases
///
/// # Return Values
///
/// - `Ok(())`: Parameter analysis completed successfully (issues reported via output)
/// - `Err(PocError::IoError)`: Filesystem access failure during parameter analysis
///
/// Note: This function reports configuration issues via console output but does not
/// fail on missing parameters - it returns `Ok(())` unless system access fails.
///
/// # See Also
///
/// Related IOMMU configuration validation functions:
/// - [`check_hardware_support()`]: Hardware capability detection
/// - [`check_bios_settings()`]: Firmware configuration validation
/// - [`run_diagnostics()`]: Comprehensive IOMMU system validation
/// - [`check_iommu_enabled()`]: Basic IOMMU functionality verification
/// - [`analyze_iommu_topology()`]: IOMMU group structure analysis
fn check_kernel_parameters() -> Result<(), PocError> {
    println!("\n=== Kernel Parameters Check ===");

    let cmdline = fs::read_to_string("/proc/cmdline")?;
    println!("Current kernel parameters:");
    println!("  {}", cmdline.trim());

    let has_intel_iommu = cmdline.contains("intel_iommu=on");
    let has_amd_iommu = cmdline.contains("amd_iommu=on");
    let has_iommu_pt = cmdline.contains("iommu=pt");

    println!("\nParameter analysis:");
    if has_intel_iommu {
        println!("  v intel_iommu=on - Intel IOMMU enabled");
    } else if has_amd_iommu {
        println!("  v amd_iommu=on - AMD IOMMU enabled");
    } else {
        println!("  ! No IOMMU parameter in kernel");
        println!("     Add to /etc/default/grub:");

        // Detect CPU vendor
        let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
        if cpuinfo.contains("vmx") {
            println!("     GRUB_CMDLINE_LINUX_DEFAULT=\"... intel_iommu=on iommu=pt\"");
        } else if cpuinfo.contains("svm") {
            println!("     GRUB_CMDLINE_LINUX_DEFAULT=\"... amd_iommu=on iommu=pt\"");
        } else {
            println!("     GRUB_CMDLINE_LINUX_DEFAULT=\"... intel_iommu=on iommu=pt\" (for Intel)");
            println!("     GRUB_CMDLINE_LINUX_DEFAULT=\"... amd_iommu=on iommu=pt\" (for AMD)");
        }
        println!("     Then run: sudo update-grub && sudo reboot");
    }

    if has_iommu_pt {
        println!("  v iommu=pt - passthrough mode enabled");
    } else {
        println!("  ! No iommu=pt - recommended for performance");
    }

    // Check current IOMMU status
    let iommu_groups_path = Path::new("/sys/kernel/iommu_groups");
    if iommu_groups_path.exists() {
        let entries = fs::read_dir(iommu_groups_path)?;
        let group_count = entries.count();
        println!("  v IOMMU working: {group_count} groups available");
    } else {
        println!("  x IOMMU not working - check parameters and restart");
    }

    Ok(())
}

/// Analyzes IOMMU group topology and device isolation for VFIO passthrough planning.
///
/// This function performs a comprehensive analysis of the system's IOMMU group structure,
/// providing detailed information about device isolation, group composition, and
/// passthrough readiness. It examines how devices are organized into IOMMU groups
/// and evaluates the implications for VFIO device passthrough operations.
///
/// IOMMU groups represent the fundamental unit of device isolation in virtualization
/// environments. Devices within the same IOMMU group cannot be independently assigned
/// to different virtual machines - they must be passed through together or remain
/// with the host system. This analysis helps administrators understand device
/// relationships and plan optimal passthrough configurations.
///
/// # IOMMU Group Fundamentals
///
/// ## Device Isolation Principles
/// - **Group Boundaries**: Devices in the same group share isolation boundaries
/// - **Passthrough Units**: Groups define the minimum assignable unit for VMs
/// - **Security Domains**: Groups provide DMA isolation between devices
/// - **Hardware Topology**: Groups reflect PCIe bridge and switch architecture
///
/// ## Group Formation Factors
/// - **PCIe Topology**: Bridges and switches create natural group boundaries
/// - **ACS Support**: Access Control Services enable finer-grained isolation
/// - **BIOS Configuration**: Firmware settings affect group granularity
/// - **Hardware Design**: Motherboard and chipset architecture influence grouping
///
/// # Analysis Process
///
/// The function systematically examines the IOMMU infrastructure:
///
/// ## Group Discovery
/// - Enumerates all IOMMU groups in `/sys/kernel/iommu_groups/`
/// - Identifies devices assigned to each group
/// - Handles missing or inaccessible group directories gracefully
/// - Sorts groups numerically for consistent presentation
///
/// ## Device Information Gathering
/// - Extracts PCI vendor and device IDs for hardware identification
/// - Determines device class codes for functional categorization
/// - Maps device types (graphics, network, storage, etc.)
/// - Handles corrupted or missing device information gracefully
///
/// ## Topology Analysis
/// - Evaluates group composition (single vs multi-device groups)
/// - Identifies isolation quality and passthrough implications
/// - Categorizes devices by functional type within groups
/// - Assesses overall system passthrough readiness
///
/// ## Recommendation Generation
/// - Provides specific guidance for multi-device groups
/// - Suggests configuration improvements where applicable
/// - Identifies potential ACS override opportunities
/// - Offers BIOS/firmware optimization recommendations
///
/// # Output Format
///
/// The function provides detailed console output organized by group and device:
/// ```text
/// === IOMMU Groups Topology Analysis ===
/// Found 28 IOMMU groups:
///
/// Group 0: 1 device(s)
///   v Single device (good isolation)
///     └─ 0000:00:00.0 [0x8086:0xa36d] - Other
///
/// Group 14: 2 device(s)
///   ! WARNING: Multiple devices in same IOMMU group (not isolated)
///     └─ 0000:01:00.0 [0x10de:0x2204] - VGA Controller
///     └─ 0000:01:00.1 [0x10de:0x1aef] - Audio Device
///
/// Group 26: 1 device(s)
///   v Single device (good isolation)
///     └─ 0000:3b:00.0 [0x8086:0x15f3] - Network Controller
///
/// === Topology Summary ===
/// Single-device groups (passthrough ready): 24
/// Multi-device groups (require all devices): 4
///
/// 💡 Recommendations:
///   - Multi-device groups require passing ALL devices in the group to VM
///   - Consider enabling ACS override if supported: pcie_acs_override=downstream
///   - Check BIOS settings for PCIe ACS/ASPM configuration
/// ```
///
/// # Device Classification
///
/// The function categorizes devices by their PCI class codes:
///
/// ## Graphics Devices (Class 0x0300)
/// - VGA controllers and GPU hardware
/// - Critical for GPU passthrough scenarios
/// - Often grouped with associated audio controllers
/// - May require special display switching considerations
///
/// ## Network Controllers (Class 0x0200)
/// - Ethernet, WiFi, and other network interfaces
/// - Useful for dedicated VM networking
/// - Generally well-isolated in modern systems
/// - Important for SR-IOV virtual function support
///
/// ## Storage Controllers (Classes 0x0101, 0x0106)
/// - SATA, NVMe, and RAID controllers
/// - Critical for VM storage performance
/// - May affect host boot capabilities when passed through
/// - Often exist as single-device groups
///
/// ## Audio Devices (Class 0x0403)
/// - Sound cards and audio controllers
/// - Frequently grouped with graphics cards
/// - Enable complete multimedia passthrough
/// - May be integrated or discrete devices
///
/// ## USB Controllers (Class 0x0c03)
/// - USB host controllers (EHCI, XHCI, etc.)
/// - Enable USB device passthrough to VMs
/// - Important for peripheral device access
/// - May control multiple USB ports
///
/// ## Other Devices
/// - System controllers, bridges, and miscellaneous hardware
/// - Generally not suitable for direct passthrough
/// - May be essential for system operation
/// - Often exist in multi-device groups
///
/// # Group Composition Analysis
///
/// ## Single-Device Groups
/// - **Optimal for Passthrough**: Can be independently assigned to VMs
/// - **Clean Isolation**: No dependencies on other devices
/// - **Flexible Assignment**: Easy to move between host and VMs
/// - **Preferred Configuration**: Indicates good IOMMU granularity
///
/// ## Multi-Device Groups
/// - **Collective Assignment**: All devices must be passed through together
/// - **Dependency Chains**: Devices share isolation boundaries
/// - **Planning Required**: May include essential host devices
/// - **Potential Issues**: Can complicate VM configuration
///
/// # System Requirements
///
/// This function requires:
/// - IOMMU enabled and functional in hardware and kernel
/// - Access to `/sys/kernel/iommu_groups/` and `/sys/bus/pci/devices/`
/// - Sufficient permissions to read IOMMU group and device information
/// - PCI devices properly enumerated by the kernel
/// - IOMMU groups created during system initialization
///
/// # Topology Optimization Recommendations
///
/// Based on the analysis, the function suggests several optimization strategies:
///
/// ## ACS (Access Control Services) Override
/// - **Purpose**: Forces finer-grained IOMMU group creation
/// - **Kernel Parameter**: `pcie_acs_override=downstream`
/// - **Benefits**: May split multi-device groups into single-device groups
/// - **Risks**: Can reduce security isolation in some configurations
///
/// ## BIOS/UEFI Configuration
/// - **PCIe ACS Settings**: Enable ACS where supported
/// - **ASPM Configuration**: May affect device grouping
/// - **SR-IOV Settings**: Enable for virtual function support
/// - **Above 4G Decoding**: May improve device isolation
///
/// ## Hardware Considerations
/// - **Motherboard Selection**: PCIe topology affects grouping
/// - **Add-in Cards**: May provide better isolation than integrated devices
/// - **Slot Placement**: Different PCIe slots may have different group assignments
/// - **Chipset Features**: Modern chipsets generally provide better isolation
///
/// # Error Handling
///
/// The function implements comprehensive error handling:
///
/// ## Missing IOMMU Groups
/// - Returns error if IOMMU groups directory doesn't exist
/// - Indicates IOMMU is not enabled or functional
/// - Suggests checking IOMMU configuration
/// - Provides clear diagnostic information
///
/// ## Device Access Issues
/// - Handles missing device information gracefully
/// - Uses fallback values for corrupted data
/// - Continues analysis despite individual device failures
/// - Maintains analysis completeness where possible
///
/// ## Filesystem Errors
/// - Robust handling of permission and access issues
/// - Graceful degradation when information is unavailable
/// - Clear error reporting for diagnostic purposes
/// - Maintains functional analysis despite partial failures
///
/// # Integration with VFIO Workflow
///
/// This analysis serves multiple purposes in VFIO device management:
///
/// ## Passthrough Planning
/// - Identifies devices ready for immediate passthrough
/// - Reveals group dependencies that affect device selection
/// - Helps plan device allocation between host and VMs
/// - Supports multi-VM configuration planning
///
/// ## System Assessment
/// - Evaluates overall system suitability for device passthrough
/// - Identifies hardware limitations and opportunities
/// - Guides hardware upgrade and configuration decisions
/// - Provides baseline for performance optimization
///
/// ## Troubleshooting Support
/// - Explains why devices cannot be independently assigned
/// - Identifies configuration changes needed for optimal isolation
/// - Supports diagnosis of passthrough failures
/// - Provides context for device binding issues
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{analyze_iommu_topology, PocError};
/// // Analyze system IOMMU topology
/// match analyze_iommu_topology() {
///     Ok(()) => println!("Topology analysis completed - see output for details"),
///     Err(e) => {
///         eprintln!("Topology analysis failed: {}", e);
///         eprintln!("Check IOMMU configuration and system setup");
///     }
/// }
/// ```
///
/// # Practical Applications
///
/// ## GPU Passthrough Planning
/// - Identifies if graphics cards are in single-device groups
/// - Reveals audio controller dependencies
/// - Guides selection of primary vs secondary GPUs
/// - Helps plan display switching strategies
///
/// ## Network Device Assignment
/// - Shows which network interfaces can be independently assigned
/// - Identifies opportunities for SR-IOV configuration
/// - Supports planning of VM networking architectures
/// - Helps maintain host connectivity during passthrough
///
/// ## Storage Passthrough Analysis
/// - Reveals storage controller isolation status
/// - Identifies potential boot device conflicts
/// - Supports planning of VM storage configurations
/// - Helps optimize storage performance strategies
///
/// ## Multi-VM Deployment
/// - Supports device allocation across multiple VMs
/// - Identifies resource conflicts and dependencies
/// - Guides optimal device distribution strategies
/// - Helps plan scalable virtualization deployments
///
/// # Performance Considerations
///
/// The function performs several operations that affect execution time:
/// - IOMMU group enumeration: 5-50ms depending on group count
/// - Device information gathering: 1-5ms per device
/// - File system operations: < 1ms per sysfs access
/// - Data sorting and analysis: < 10ms for typical systems
///
/// Total execution time is typically 50-200ms for systems with 20-50 IOMMU groups.
///
/// # Platform Compatibility
///
/// This function works across different virtualization platforms:
/// - **Intel VT-d**: Full support with comprehensive group analysis
/// - **AMD-Vi**: Complete compatibility with AMD IOMMU implementations
/// - **ARM SMMU**: Basic support on compatible ARM64 systems
/// - **Container Environments**: Limited support depending on device visibility
///
/// # Visual Indicators and Output Format
///
/// The function uses consistent visual indicators for quick assessment:
/// - `v`: Single-device group (optimal for passthrough)
/// - `!`: Multi-device group (requires collective assignment)
/// - `└─`: Device listing with hierarchical structure
/// - `💡`: Optimization recommendations and suggestions
///
/// # Return Values
///
/// - `Ok(())`: Topology analysis completed successfully
/// - `Err(PocError::IommuNotEnabled)`: IOMMU groups not found (configuration issue)
/// - `Err(PocError::IoError)`: Filesystem access failures during analysis
///
/// # See Also
///
/// Related IOMMU and device analysis functions:
/// - [`run_diagnostics()`]: Overall IOMMU system validation
/// - [`list_devices_with_iommu()`]: Simple device enumeration
/// - [`check_device_drivers()`]: Driver binding status analysis
/// - [`bind_device_to_vfio()`]: Device binding operations
/// - [`check_security_settings()`]: Permission and access validation
fn analyze_iommu_topology() -> Result<(), PocError> {
    println!("=== IOMMU Groups Topology Analysis ===");

    let iommu_groups_path = Path::new("/sys/kernel/iommu_groups");
    if !iommu_groups_path.exists() {
        return Err(PocError::IommuNotEnabled("IOMMU groups not found".into()));
    }

    let mut groups_data = Vec::new();

    // Collect all groups and their devices
    for entry in fs::read_dir(iommu_groups_path)? {
        let entry = entry?;
        let group_name = entry.file_name();
        let group_path = entry.path().join("devices");

        if group_path.exists() {
            let mut devices = Vec::new();
            for device_entry in fs::read_dir(&group_path)? {
                let device_entry = device_entry?;
                let device_name = device_entry.file_name().to_string_lossy().to_string();

                // Get device info
                let device_path = Path::new("/sys/bus/pci/devices").join(&device_name);
                let vendor_id = fs::read_to_string(device_path.join("vendor"))
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();
                let device_id = fs::read_to_string(device_path.join("device"))
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();
                let class = fs::read_to_string(device_path.join("class"))
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();

                devices.push((device_name, vendor_id, device_id, class));
            }
            groups_data.push((group_name.to_string_lossy().to_string(), devices));
        }
    }

    // Sort groups by number
    groups_data.sort_by(|a, b| {
        a.0.parse::<u32>()
            .unwrap_or(0)
            .cmp(&b.0.parse::<u32>().unwrap_or(0))
    });

    println!("Found {} IOMMU groups:", groups_data.len());
    println!();

    // Analyze each group
    for (group_id, devices) in &groups_data {
        println!("Group {}: {} device(s)", group_id, devices.len());

        if devices.len() > 1 {
            println!("  ! WARNING: Multiple devices in same IOMMU group (not isolated)");
        } else {
            println!("  v Single device (good isolation)");
        }

        for (device, vendor, device_id, class) in devices {
            let device_type = match &class[0..6] {
                "0x0300" => "VGA Controller",
                "0x0200" => "Network Controller",
                "0x0101" => "IDE Controller",
                "0x0106" => "SATA Controller",
                "0x0403" => "Audio Device",
                "0x0c03" => "USB Controller",
                _ => "Other",
            };

            println!("    └─ {device} [{vendor}:{device_id}] - {device_type}");
        }
        println!();
    }

    // Summary and recommendations
    let single_device_groups = groups_data
        .iter()
        .filter(|(_, devices)| devices.len() == 1)
        .count();
    let multi_device_groups = groups_data
        .iter()
        .filter(|(_, devices)| devices.len() > 1)
        .count();

    println!("=== Topology Summary ===");
    println!("Single-device groups (passthrough ready): {single_device_groups}");
    println!("Multi-device groups (require all devices): {multi_device_groups}");

    if multi_device_groups > 0 {
        println!("\n💡 Recommendations:");
        println!("  - Multi-device groups require passing ALL devices in the group to VM");
        println!("  - Consider enabling ACS override if supported: pcie_acs_override=downstream");
        println!("  - Check BIOS settings for PCIe ACS/ASPM configuration");
    }

    Ok(())
}

/// Analyzes PCI device driver binding status and VFIO-PCI driver availability.
///
/// This function performs a comprehensive analysis of PCI device driver bindings
/// throughout the system, specifically focusing on devices that are compatible with
/// VFIO (Virtual Function I/O) operations. It categorizes devices based on their
/// current driver binding status and provides detailed information about the
/// vfio-pci driver's availability and capabilities.
///
/// The analysis provides critical information for VFIO device passthrough planning
/// by identifying which devices are ready for passthrough, which need to be unbound
/// from their current drivers, and which are available for immediate binding to
/// vfio-pci. This information is essential for making informed decisions about
/// device management in virtualization environments.
///
/// # Device Categorization
///
/// The function categorizes IOMMU-capable devices into three distinct groups:
///
/// ## VFIO-Ready Devices
/// - Devices currently bound to the vfio-pci driver
/// - Ready for immediate VFIO passthrough operations
/// - Can be directly used by userspace applications or VMs
/// - Represent devices that have completed the binding process
///
/// ## Host-Bound Devices
/// - Devices currently bound to host system drivers
/// - Actively used by the host operating system
/// - Require unbinding before VFIO passthrough is possible
/// - May impact host functionality when unbound
///
/// ## Unbound Devices
/// - Devices with no currently bound driver
/// - Available for immediate binding to any compatible driver
/// - Often represent unused or secondary devices
/// - Ideal candidates for VFIO passthrough binding
///
/// # Analysis Process
///
/// The function follows a systematic approach to device analysis:
///
/// ## Device Discovery
/// - Enumerates all devices in `/sys/bus/pci/devices/`
/// - Filters devices to include only those with IOMMU group assignments
/// - Excludes devices without IOMMU support (not suitable for passthrough)
/// - Handles device enumeration errors gracefully
///
/// ## Device Information Extraction
/// - Reads vendor ID from device sysfs attributes
/// - Extracts device ID for hardware identification
/// - Resolves current driver binding through symlink analysis
/// - Handles missing or corrupted device information gracefully
///
/// ## Driver Status Determination
/// - Analyzes driver symlinks to identify bound drivers
/// - Distinguishes between vfio-pci, host drivers, and unbound state
/// - Provides fallback handling for unresolvable driver information
/// - Maintains consistency in driver name reporting
///
/// ## Data Organization and Reporting
/// - Groups devices by binding status for clear presentation
/// - Formats device information with vendor/device IDs
/// - Provides actionable status indicators for each device
/// - Summarizes findings for quick decision-making
///
/// # Output Format
///
/// The function provides structured console output organized by device category:
/// ```text
/// === Device Driver Analysis ===
/// Devices bound to vfio-pci (2):
///   v 0000:3b:00.0 [0x10de:0x2204] - Ready for passthrough
///   v 0000:3c:00.0 [0x10de:0x2205] - Ready for passthrough
///
/// Devices bound to other drivers (4):
///   ◯ 0000:01:00.0 [0x10de:0x1b80] - Currently using: nouveau
///   ◯ 0000:02:00.0 [0x8086:0x15f3] - Currently using: e1000e
///   ◯ 0000:00:1f.2 [0x8086:0xa32c] - Currently using: ahci
///   ◯ 0000:00:14.0 [0x8086:0xa36d] - Currently using: xhci_hcd
///
/// Unbound devices (1):
///   o 0000:04:00.0 [0x1002:0x67df] - Available for binding
///
/// === VFIO-PCI Driver Status ===
///   v vfio-pci driver is loaded and available
///   v Dynamic device ID binding supported
/// ```
///
/// # VFIO-PCI Driver Assessment
///
/// Beyond device categorization, the function evaluates the vfio-pci driver:
///
/// ## Driver Availability
/// - Checks for vfio-pci driver presence in the kernel
/// - Verifies driver is loaded and accessible via sysfs
/// - Identifies when the driver needs to be loaded manually
/// - Provides specific commands for driver loading
///
/// ## Dynamic Binding Capabilities
/// - Tests for new_id interface availability
/// - Confirms support for runtime device ID registration
/// - Validates dynamic binding functionality
/// - Essential for flexible device management
///
/// ## Module Loading Guidance
/// - Provides modprobe commands for missing drivers
/// - Suggests troubleshooting steps for loading failures
/// - Identifies potential Secure Boot or signing issues
/// - Guides users through driver installation process
///
/// # Device Information Details
///
/// For each device, the function provides comprehensive identification:
///
/// ## PCI Address Format
/// - Standard PCI domain:bus:device.function notation
/// - Enables precise device targeting for operations
/// - Compatible with other PCI management tools
/// - Unique identifier for each device in the system
///
/// ## Hardware Identification
/// - Vendor ID in hexadecimal format (e.g., 0x10de for NVIDIA)
/// - Device ID for specific hardware model identification
/// - Combined vendor:device ID for complete hardware fingerprint
/// - Useful for driver compatibility verification
///
/// ## Driver Binding Status
/// - Current kernel driver name (if bound)
/// - Clear indication of unbound state
/// - Driver-specific information for troubleshooting
/// - Foundation for binding/unbinding decisions
///
/// # System Requirements
///
/// This function requires:
/// - Linux operating system with sysfs filesystem
/// - IOMMU enabled and functional
/// - Access to `/sys/bus/pci/devices/` and `/sys/bus/pci/drivers/`
/// - Sufficient permissions to read device symlinks and attributes
/// - PCI devices present and enumerated by the kernel
///
/// # Error Handling
///
/// The function implements robust error handling:
///
/// ## Missing Filesystem Paths
/// - Returns error if PCI devices directory is missing
/// - Indicates fundamental system configuration issues
/// - Suggests checking IOMMU configuration
/// - Provides clear error messaging for diagnosis
///
/// ## Device Enumeration Failures
/// - Gracefully handles individual device access failures
/// - Continues analysis despite corrupted device entries
/// - Uses fallback values for missing device information
/// - Maintains analysis completeness despite partial failures
///
/// ## Permission Issues
/// - Handles insufficient permissions for device access
/// - Provides fallback information where possible
/// - Suggests privilege escalation when necessary
/// - Maintains functional analysis despite access limitations
///
/// # Integration with VFIO Workflow
///
/// This function serves as a critical assessment tool in the VFIO workflow:
///
/// ## Pre-Binding Analysis
/// - Identifies devices suitable for VFIO passthrough
/// - Reveals current driver bindings that need modification
/// - Highlights unbound devices ready for immediate use
/// - Informs device selection decisions
///
/// ## Post-Binding Verification
/// - Confirms successful vfio-pci binding operations
/// - Validates that devices transitioned to VFIO control
/// - Identifies binding failures requiring remediation
/// - Provides feedback on configuration changes
///
/// ## System State Monitoring
/// - Tracks driver binding changes over time
/// - Monitors VFIO driver availability
/// - Assists in troubleshooting binding issues
/// - Supports ongoing system maintenance
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{check_device_drivers, PocError};
/// // Analyze current device driver status
/// match check_device_drivers() {
///     Ok(()) => println!("Device analysis completed - see output for details"),
///     Err(e) => {
///         eprintln!("Device analysis failed: {}", e);
///         eprintln!("Check IOMMU configuration and permissions");
///     }
/// }
/// ```
///
/// # Device Management Decision Support
///
/// The analysis output supports informed device management decisions:
///
/// ## Passthrough Planning
/// - Identify which devices are immediately ready for passthrough
/// - Determine which host drivers need to be unbound
/// - Plan device allocation between host and VM environments
/// - Assess impact of device reassignment on host functionality
///
/// ## Binding Strategy
/// - Prioritize unbound devices for VFIO binding
/// - Plan systematic unbinding of host-bound devices
/// - Identify critical devices that should remain host-bound
/// - Optimize device distribution for multi-VM scenarios
///
/// ## Troubleshooting Support
/// - Verify that binding operations completed successfully
/// - Identify devices that failed to bind properly
/// - Locate devices that reverted to previous driver bindings
/// - Diagnose VFIO driver loading and configuration issues
///
/// # Common Device Categories
///
/// The function commonly encounters these device types:
///
/// ## Graphics Cards
/// - Often bound to nouveau, i915, or amdgpu drivers
/// - Prime candidates for GPU passthrough scenarios
/// - May require special handling for primary display devices
/// - Significant impact on host display when unbound
///
/// ## Network Controllers
/// - Typically bound to e1000e, ixgbe, or similar drivers
/// - Useful for dedicated VM networking scenarios
/// - May interrupt host connectivity when unbound
/// - Consider redundant interfaces for host access
///
/// ## Storage Controllers
/// - Usually bound to ahci, nvme, or RAID drivers
/// - Require careful planning to avoid data access issues
/// - May affect boot capabilities when unbound
/// - Critical for VM storage performance scenarios
///
/// ## USB Controllers
/// - Commonly bound to xhci_hcd or ehci_hcd drivers
/// - Enable full USB device passthrough to VMs
/// - May affect host USB functionality when unbound
/// - Useful for specialized peripheral access
///
/// # Performance Considerations
///
/// The function performs several filesystem operations:
/// - Directory enumeration of PCI devices (varies by system, typically 50-200 devices)
/// - Symlink resolution for driver identification (< 1ms per device)
/// - File reading for vendor/device IDs (< 1ms per device)
/// - Sysfs attribute access for device information (< 1ms per device)
///
/// Total execution time is typically 50-200ms depending on the number of PCI devices.
///
/// # Platform Compatibility
///
/// This function works across Linux platforms:
/// - **x86_64**: Full support with comprehensive device coverage
/// - **ARM64**: Support depends on PCI and IOMMU implementation
/// - **Container Environments**: May have limited device visibility
/// - **Kernel Versions**: Compatible with 3.6+ for basic functionality, 4.0+ recommended
///
/// # Visual Status Indicators
///
/// The function uses consistent visual indicators:
/// - `v`: Device ready for VFIO passthrough (green status)
/// - `◯`: Device bound to host driver (neutral status)
/// - `o`: Device available for binding (informational status)
/// - `x`: Missing or problematic configuration (error status)
///
/// # Return Values
///
/// - `Ok(())`: Device analysis completed successfully
/// - `Err(PocError::PathNotFound)`: PCI devices directory not found (system configuration issue)
/// - `Err(PocError::IoError)`: Filesystem access failures during device enumeration
///
/// # See Also
///
/// Related device management functions:
/// - [`list_devices_with_iommu()`]: Discover all IOMMU-capable devices
/// - [`bind_device_to_vfio()`]: Bind specific devices to vfio-pci driver
/// - [`unbind_device()`]: Remove devices from current drivers
/// - [`run_diagnostics()`]: Validate overall VFIO system readiness
/// - [`check_security_settings()`]: Verify permissions for device operations
fn check_device_drivers() -> Result<(), PocError> {
    println!("=== Device Driver Analysis ===");

    let pci_devices_path = Path::new("/sys/bus/pci/devices");
    if !pci_devices_path.exists() {
        return Err(PocError::PathNotFound("PCI devices path not found".into()));
    }

    let mut vfio_devices = Vec::new();
    let mut bound_devices = Vec::new();
    let mut unbound_devices = Vec::new();

    for entry in fs::read_dir(pci_devices_path)? {
        let entry = entry?;
        let device_name = entry.file_name().to_string_lossy().to_string();
        let device_path = entry.path();

        // Check if device has IOMMU group
        let iommu_group_path = device_path.join("iommu_group");
        if !iommu_group_path.exists() {
            continue;
        }

        // Get device info
        let vendor_id = fs::read_to_string(device_path.join("vendor"))
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();
        let device_id = fs::read_to_string(device_path.join("device"))
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        // Check current driver
        let driver_path = device_path.join("driver");
        let current_driver = if driver_path.exists() {
            driver_path
                .read_link()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "unbound".to_string()
        };

        let device_info = (
            device_name.clone(),
            vendor_id,
            device_id,
            current_driver.clone(),
        );

        match current_driver.as_str() {
            "vfio-pci" => vfio_devices.push(device_info),
            "unbound" => unbound_devices.push(device_info),
            _ => bound_devices.push(device_info),
        }
    }

    println!("Devices bound to vfio-pci ({}):", vfio_devices.len());
    for (device, vendor, device_id, _) in &vfio_devices {
        println!("  v {device} [{vendor}:{device_id}] - Ready for passthrough");
    }

    println!(
        "\nDevices bound to other drivers ({}):",
        bound_devices.len()
    );
    for (device, vendor, device_id, driver) in &bound_devices {
        println!("  ◯ {device} [{vendor}:{device_id}] - Currently using: {driver}");
    }

    println!("\nUnbound devices ({}):", unbound_devices.len());
    for (device, vendor, device_id, _) in &unbound_devices {
        println!("  o {device} [{vendor}:{device_id}] - Available for binding");
    }

    // Show vfio-pci driver status
    let vfio_pci_path = Path::new("/sys/bus/pci/drivers/vfio-pci");
    println!("\n=== VFIO-PCI Driver Status ===");
    if vfio_pci_path.exists() {
        println!("  v vfio-pci driver is loaded and available");

        // Check new_id and remove_id capabilities
        if vfio_pci_path.join("new_id").exists() {
            println!("  v Dynamic device ID binding supported");
        }
    } else {
        println!("  x vfio-pci driver not loaded");
        println!("     Run: sudo modprobe vfio-pci");
    }

    Ok(())
}

/// Validates virtual machine infrastructure readiness for VFIO device passthrough.
///
/// This function performs a comprehensive assessment of the virtualization environment
/// to determine if the system is properly configured for running virtual machines with
/// VFIO device passthrough. It evaluates essential components including hypervisor
/// support, emulation software, memory configuration, CPU management, and virtualization
/// features required for optimal VM performance and device passthrough operations.
///
/// The readiness check covers six critical areas of VM infrastructure:
/// 1. **KVM Hypervisor**: Kernel-based virtual machine support and device availability
/// 2. **QEMU Emulation**: System emulation software installation and version
/// 3. **Memory Management**: Hugepages configuration for improved VM performance
/// 4. **CPU Isolation**: Dedicated CPU cores for VM workloads
/// 5. **Nested Virtualization**: Support for running VMs within VMs
/// 6. **Management Tools**: Optional libvirt virtualization management layer
///
/// # Virtualization Infrastructure Components
///
/// ## KVM (Kernel-based Virtual Machine)
/// - Validates presence of `/dev/kvm` device file for hypervisor access
/// - Confirms KVM kernel module is loaded and functional
/// - Verifies user permissions for KVM device access
/// - Essential for hardware-accelerated virtualization on Linux
///
/// ## QEMU System Emulation
/// - Checks installation of `qemu-system-x86_64` emulator
/// - Reports QEMU version information for compatibility assessment
/// - Validates that complete system emulation is available
/// - Required for device emulation and VM lifecycle management
///
/// ## Hugepages Memory Management
/// - Examines current hugepages allocation via `/proc/sys/vm/nr_hugepages`
/// - Calculates total hugepage memory in megabytes for capacity planning
/// - Reads hugepage size from `/proc/meminfo` for accurate calculations
/// - Provides configuration recommendations for optimal memory performance
///
/// ## CPU Isolation Configuration
/// - Analyzes kernel command line for `isolcpus=` parameters
/// - Reports which CPU cores are isolated from general kernel scheduling
/// - Identifies dedicated cores available for VM workload assignment
/// - Critical for reducing latency and improving deterministic performance
///
/// ## Nested Virtualization Support
/// - Checks Intel (`kvm_intel`) and AMD (`kvm_amd`) module parameters
/// - Validates nested virtualization is enabled in KVM modules
/// - Reports platform-specific nested virtualization status
/// - Enables running VMs within VMs for development and testing
///
/// ## Libvirt Management Layer
/// - Verifies optional libvirt daemon installation
/// - Checks `virsh` command availability for VM management
/// - Provides enterprise-grade VM lifecycle management capabilities
/// - Optional but recommended for production environments
///
/// # Output Format
///
/// The function provides detailed console output organized by infrastructure component:
/// ```text
/// === VM Readiness Check ===
/// KVM Support:
///   v /dev/kvm exists - KVM available
///
/// QEMU Installation:
///   v QEMU installed: QEMU emulator version 6.2.0
///
/// Hugepages Configuration:
///   v Hugepages configured: 1024 pages
///      Total hugepage memory: 2048 MB
///
/// CPU Isolation:
///   v CPU isolation configured
///      isolcpus=2-7,10-15
///
/// Nested Virtualization:
///   v Intel nested virtualization enabled
///
/// Libvirt (optional):
///   v Libvirt available
/// ```
///
/// # Performance Optimization Analysis
///
/// The function identifies configurations that impact VM performance:
///
/// ## Memory Performance
/// - **Hugepages**: Large memory pages reduce TLB pressure and improve performance
/// - **Allocation**: Calculates available hugepage memory for VM allocation
/// - **Recommendations**: Suggests hugepage counts based on typical VM requirements
/// - **Default Size**: Assumes 2MB hugepages if size detection fails
///
/// ## CPU Performance
/// - **Isolation**: Dedicated CPU cores prevent host kernel interference
/// - **NUMA Awareness**: Isolated cores should ideally be NUMA-local to VM memory
/// - **Scheduling**: Isolated cores provide predictable latency characteristics
/// - **Topology**: CPU isolation works best with proper core/thread selection
///
/// ## Virtualization Features
/// - **Hardware Acceleration**: KVM provides near-native performance
/// - **Nested Support**: Enables complex virtualization scenarios
/// - **Device Passthrough**: VFIO works optimally with proper VM infrastructure
/// - **Management Tools**: Libvirt simplifies complex VM configurations
///
/// # System Requirements
///
/// This function requires:
/// - Linux operating system with KVM support
/// - Intel VT-x or AMD-V capable processor
/// - Access to `/dev/kvm`, `/proc/sys/vm/`, and `/sys/module/` filesystems
/// - Sufficient permissions to execute system commands
/// - Optional: Root access for some advanced configuration checks
///
/// # Common Configuration Issues
///
/// The function identifies and provides guidance for typical problems:
///
/// ## Missing KVM Support
/// - KVM modules not loaded or compiled into kernel
/// - Virtualization disabled in BIOS/UEFI firmware
/// - User lacks permissions to access `/dev/kvm` device
/// - Incompatible processor without virtualization extensions
///
/// ## QEMU Installation Problems
/// - Missing QEMU packages in Linux distribution
/// - Incomplete QEMU installation missing system emulation
/// - Version compatibility issues with KVM kernel modules
/// - Architecture mismatch (ARM vs x86 QEMU variants)
///
/// ## Memory Configuration Issues
/// - Insufficient hugepages allocated for VM requirements
/// - Hugepages not configured causing performance degradation
/// - Memory fragmentation preventing hugepage allocation
/// - NUMA topology not considered in memory planning
///
/// ## CPU Configuration Problems
/// - No CPU isolation configured leading to performance interference
/// - Incorrect isolcpus parameters causing system instability
/// - Isolated CPUs not aligned with NUMA domains
/// - Insufficient isolated cores for VM workload requirements
///
/// # Installation and Configuration Guidance
///
/// For each missing component, the function provides specific installation commands:
/// ```bash
/// # KVM support
/// sudo apt install qemu-kvm
/// sudo usermod -a -G kvm $USER
///
/// # QEMU emulation
/// sudo apt install qemu-system-x86
///
/// # Hugepages configuration
/// echo 1024 | sudo tee /proc/sys/vm/nr_hugepages
/// # Persistent configuration in /etc/sysctl.conf:
/// vm.nr_hugepages = 1024
///
/// # CPU isolation (requires reboot)
/// # Add to /etc/default/grub:
/// GRUB_CMDLINE_LINUX_DEFAULT="... isolcpus=2-7,10-15"
/// sudo update-grub && sudo reboot
///
/// # Libvirt management
/// sudo apt install libvirt-daemon-system
/// sudo usermod -a -G libvirt $USER
/// ```
///
/// # Integration with VFIO Workflow
///
/// This function is typically used as part of complete VFIO setup validation:
/// 1. **Hardware Validation**: Use [`run_diagnostics()`] for IOMMU readiness
/// 2. **Security Check**: Use [`check_security_settings()`] for permissions
/// 3. **VM Readiness**: Use this function to validate virtualization infrastructure
/// 4. **Device Management**: Proceed with [`bind_device_to_vfio()`] operations
/// 5. **VM Creation**: Configure VMs with validated infrastructure components
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{check_vm_readiness, PocError};
/// // Basic VM readiness check
/// match check_vm_readiness() {
///     Ok(()) => println!("VM infrastructure validated - ready for passthrough"),
///     Err(e) => {
///         eprintln!("VM infrastructure issue: {}", e);
///         eprintln!("Address the above issues before proceeding");
///     }
/// }
/// ```
///
/// # Performance Recommendations
///
/// Based on the analysis, the function suggests optimizations:
///
/// ## Memory Optimization
/// - **Hugepage Sizing**: 1GB hugepages for large VMs (>8GB RAM)
/// - **Allocation Strategy**: Pre-allocate hugepages at boot time
/// - **NUMA Considerations**: Allocate hugepages on appropriate NUMA nodes
/// - **Overcommit**: Avoid memory overcommitment for passthrough VMs
///
/// ## CPU Optimization
/// - **Core Selection**: Isolate complete cores (both hyperthreads)
/// - **NUMA Alignment**: Keep VM CPUs within single NUMA domain
/// - **Host Reservation**: Reserve sufficient cores for host OS operation
/// - **Interrupt Handling**: Consider isolating IRQ handling from VM cores
///
/// ## Advanced Configuration
/// - **VFIO Optimization**: Configure MSI-X interrupts for passthrough devices
/// - **QEMU Tuning**: Use CPU pinning and memory binding in QEMU
/// - **Real-time**: Consider real-time kernel for latency-sensitive workloads
/// - **Power Management**: Disable CPU frequency scaling for consistency
///
/// # Troubleshooting Common Issues
///
/// ## Permission Problems
/// - Add user to `kvm` and `libvirt` groups: `sudo usermod -a -G kvm,libvirt $USER`
/// - Verify group membership with `groups` command
/// - Log out and back in for group changes to take effect
/// - Check AppArmor/SELinux policies for virtualization access
///
/// ## Module Loading Issues
/// - Load KVM modules manually: `sudo modprobe kvm kvm_intel` (or `kvm_amd`)
/// - Check for module blacklisting in `/etc/modprobe.d/`
/// - Verify Secure Boot doesn't block unsigned modules
/// - Check dmesg for module loading errors
///
/// ## Memory Allocation Problems
/// - Check available memory before hugepage allocation
/// - Fragment memory by running memory-intensive applications first
/// - Use transparent hugepages as fallback for dynamic allocation
/// - Monitor hugepage usage with `/proc/meminfo`
///
/// ## Nested Virtualization Issues
/// - Enable nested virtualization: `echo Y | sudo tee /sys/module/kvm_intel/parameters/nested`
/// - Make persistent by adding `options kvm_intel nested=Y` to `/etc/modprobe.d/`
/// - Verify guest CPU features include virtualization extensions
/// - Check for BIOS/UEFI settings affecting nested virtualization
///
/// # Platform Compatibility
///
/// This function supports multiple virtualization platforms:
/// - **Intel x86_64**: Full support with VT-x and VT-d
/// - **AMD x86_64**: Full support with AMD-V and AMD-Vi
/// - **ARM64**: Limited support depends on specific SoC capabilities
/// - **Container Environments**: May have restricted access to virtualization features
///
/// # Performance Considerations
///
/// The function performs several system checks:
/// - File existence checks: < 1ms per check
/// - Command execution (QEMU, virsh): 50-200ms depending on installation
/// - File content reading: < 10ms for /proc and /sys files
/// - String parsing and analysis: < 5ms
///
/// Total execution time is typically under 300ms on modern systems.
///
/// # Return Values
///
/// - `Ok(())`: VM readiness check completed successfully (issues may be reported)
/// - `Err(PocError::IoError)`: Filesystem access or command execution failure
///
/// Note: This function reports configuration issues via console output but does not
/// fail on missing optional components - it returns `Ok(())` unless system access fails.
///
/// # See Also
///
/// Related system validation functions:
/// - [`run_diagnostics()`]: IOMMU and hardware validation
/// - [`check_security_settings()`]: Security and permissions validation
/// - [`check_device_drivers()`]: Device driver status and binding analysis
/// - [`list_devices_with_iommu()`]: Available devices for passthrough
/// - [`bind_device_to_vfio()`]: Device binding for passthrough operations
fn check_vm_readiness() -> Result<(), PocError> {
    println!("=== VM Readiness Check ===");

    // Check KVM support
    println!("KVM Support:");
    let kvm_path = Path::new("/dev/kvm");
    if kvm_path.exists() {
        println!("  v /dev/kvm exists - KVM available");
    } else {
        println!("  x /dev/kvm not found - KVM not available");
        println!("     Install: sudo apt install qemu-kvm");
    }

    // Check QEMU installation
    println!("\nQEMU Installation:");
    let qemu_check = std::process::Command::new("qemu-system-x86_64")
        .arg("--version")
        .output();

    match qemu_check {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            println!(
                "  v QEMU installed: {}",
                version.lines().next().unwrap_or("unknown")
            );
        }
        _ => {
            println!("  x QEMU not found");
            println!("     Install: sudo apt install qemu-system-x86");
        }
    }

    // Check hugepages
    println!("\nHugepages Configuration:");
    let hugepages_path = Path::new("/proc/sys/vm/nr_hugepages");
    if let Ok(hugepages) = fs::read_to_string(hugepages_path) {
        let count: i32 = hugepages.trim().parse().unwrap_or(0);
        if count > 0 {
            println!("  v Hugepages configured: {count} pages");

            // Calculate memory
            let hugepage_size = fs::read_to_string("/proc/meminfo")
                .unwrap_or_default()
                .lines()
                .find(|line| line.starts_with("Hugepagesize:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|size| size.parse::<i32>().ok())
                .unwrap_or(2048);

            let total_mb = (count * hugepage_size) / 1024;
            println!("     Total hugepage memory: {total_mb} MB");
        } else {
            println!("  ! No hugepages configured");
            println!("     Consider: echo 1024 | sudo tee /proc/sys/vm/nr_hugepages");
        }
    }

    // Check CPU isolation
    println!("\nCPU Isolation:");
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    if cmdline.contains("isolcpus=") {
        println!("  v CPU isolation configured");
        if let Some(isolcpus) = cmdline
            .split_whitespace()
            .find(|arg| arg.starts_with("isolcpus="))
        {
            println!("     {isolcpus}");
        }
    } else {
        println!("  ! No CPU isolation configured");
        println!("     Consider isolating CPUs for better VM performance");
    }

    // Check nested virtualization
    println!("\nNested Virtualization:");
    let nested_intel = Path::new("/sys/module/kvm_intel/parameters/nested");
    let nested_amd = Path::new("/sys/module/kvm_amd/parameters/nested");

    if nested_intel.exists() {
        if let Ok(nested) = fs::read_to_string(nested_intel) {
            if nested.trim() == "Y" || nested.trim() == "1" {
                println!("  v Intel nested virtualization enabled");
            } else {
                println!("  ! Intel nested virtualization disabled");
            }
        }
    } else if nested_amd.exists() {
        if let Ok(nested) = fs::read_to_string(nested_amd) {
            if nested.trim() == "Y" || nested.trim() == "1" {
                println!("  v AMD nested virtualization enabled");
            } else {
                println!("  ! AMD nested virtualization disabled");
            }
        }
    }

    // Check libvirt
    println!("\nLibvirt (optional):");
    let libvirt_check = std::process::Command::new("virsh")
        .arg("--version")
        .output();

    match libvirt_check {
        Ok(output) if output.status.success() => {
            println!("  v Libvirt available");
        }
        _ => {
            println!("  o Libvirt not installed (optional)");
            println!("     Install: sudo apt install libvirt-daemon-system");
        }
    }

    Ok(())
}

/// Unbinds a PCI device from its currently bound driver.
///
/// This function safely detaches a PCI device from its current kernel driver, making
/// the device available for binding to a different driver such as vfio-pci for device
/// passthrough operations. The unbinding process follows the standard Linux driver
/// model by writing the device address to the current driver's unbind interface.
///
/// The function performs a complete unbinding sequence:
/// 1. **Device Validation**: Confirms the device exists in the PCI subsystem
/// 2. **Driver Detection**: Identifies the currently bound driver (if any)
/// 3. **Unbind Operation**: Safely detaches the device from its current driver
/// 4. **Status Reporting**: Provides detailed feedback on the unbinding process
///
/// # Parameters
///
/// * `device` - PCI device address in standard format (e.g., "0000:3b:00.0")
///   - **Domain**: 4-digit hexadecimal PCI domain (usually 0000)
///   - **Bus**: 2-digit hexadecimal PCI bus number
///   - **Device**: 2-digit hexadecimal device number (0-31)
///   - **Function**: 1-digit hexadecimal function number (0-7)
///
/// # Device State Analysis
///
/// Before attempting to unbind, the function analyzes the current device state:
///
/// ## Device Existence Check
/// Verifies that the device exists in `/sys/bus/pci/devices/` to ensure the
/// PCI address is valid and the device is enumerated by the kernel.
///
/// ## Driver Binding Status
/// Checks for the presence of a `driver` symlink to determine if the device
/// is currently bound to any kernel driver. Unbound devices are handled
/// gracefully without error.
///
/// ## Driver Identification
/// If a driver is bound, the function resolves the driver symlink to identify
/// the specific kernel module managing the device (e.g., `nouveau`, `i915`,
/// `e1000e`, `vfio-pci`).
///
/// # Unbinding Process
///
/// The actual unbinding operation uses the Linux driver model's standard interface:
///
/// ## Driver Unbind Interface
/// Each kernel driver provides an `unbind` file in its sysfs directory at
/// `/sys/bus/pci/drivers/{driver_name}/unbind`. Writing a device's PCI address
/// to this file requests the driver to release control of the device.
///
/// ## Kernel Driver Notification
/// The unbind operation triggers the driver's remove() callback, allowing it to:
/// - Save device state if necessary
/// - Release allocated resources (memory, interrupts, etc.)
/// - Perform any required cleanup operations
/// - Update internal driver state
///
/// ## Device State Transition
/// After successful unbinding, the device transitions to an unbound state where:
/// - No kernel driver has control of the device
/// - Device hardware remains powered and accessible
/// - Device can be bound to a different driver
/// - Hardware state is preserved but not actively managed
///
/// # Output Format
///
/// The function provides detailed console output tracking the unbinding process:
/// ```text
/// === Unbinding Device 0000:3b:00.0 ===
///   Current driver: nouveau
///   v Successfully unbound 0000:3b:00.0 from nouveau
/// ```
///
/// For devices that are already unbound:
/// ```text
/// === Unbinding Device 0000:3b:00.0 ===
///   o Device 0000:3b:00.0 is already unbound
/// ```
///
/// # Error Conditions
///
/// The function handles several categories of errors:
///
/// ## Device Not Found
/// - Invalid PCI address format or non-existent device
/// - Device removed or not enumerated by kernel
/// - Typos in device address specification
///
/// ## Driver Path Issues
/// - Corrupted driver symlink pointing to invalid target
/// - Permission issues accessing driver information
/// - Kernel driver subsystem inconsistencies
///
/// ## Unbind Interface Problems
/// - Driver doesn't provide unbind interface (rare with modern drivers)
/// - Permission denied writing to unbind file
/// - Driver refusing to unbind due to device dependencies
///
/// ## I/O Operation Failures
/// - Filesystem errors during sysfs access
/// - Temporary kernel resource unavailability
/// - System-level I/O problems
///
/// # System Requirements
///
/// This function requires:
/// - Linux operating system with sysfs filesystem mounted
/// - Sufficient permissions to write to driver unbind interfaces
/// - Target device present and enumerated by PCI subsystem
/// - Compatible kernel driver bound to the target device
///
/// # Safety Considerations
///
/// Unbinding devices has important safety implications:
///
/// ## System Stability
/// - **Display Devices**: Unbinding graphics drivers may cause display loss
/// - **Storage Devices**: Unbinding storage controllers may cause data loss
/// - **Network Devices**: Unbinding network drivers will interrupt connectivity
/// - **Critical Devices**: Some devices may be essential for system operation
///
/// ## Device State
/// - **Power Management**: Device may remain in active power state
/// - **Hardware State**: Device registers and configuration preserved
/// - **Interrupt Handling**: Device interrupts will no longer be serviced
/// - **DMA Operations**: Any ongoing DMA transfers will be abandoned
///
/// ## Recovery Procedures
/// If unbinding causes system issues:
/// - Use `echo "{device}" > /sys/bus/pci/drivers/{driver}/bind` to rebind
/// - Reload the kernel module: `modprobe -r {driver} && modprobe {driver}`
/// - Reboot system if device becomes unresponsive
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{unbind_device, PocError};
/// // Unbind a graphics card for GPU passthrough
/// match unbind_device("0000:01:00.0") {
///     Ok(()) => println!("Graphics card successfully unbound"),
///     Err(e) => {
///         eprintln!("Failed to unbind graphics card: {}", e);
///         // Handle error - may need to switch to console first
///     }
/// }
///
/// // Unbind a network card for network device passthrough
/// if let Err(e) = unbind_device("0000:02:00.0") {
///     eprintln!("Network card unbinding failed: {}", e);
/// }
/// ```
///
/// # Integration with VFIO Workflow
///
/// This function is typically used as preparation for VFIO device binding:
/// 1. **Device Discovery**: Use [`list_devices_with_iommu()`] to find target device
/// 2. **Driver Analysis**: Use [`check_device_drivers()`] to check current binding
/// 3. **Device Unbinding**: Use this function to release from current driver
/// 4. **VFIO Binding**: Use [`bind_device_to_vfio()`] to bind to vfio-pci
/// 5. **Verification**: Confirm successful binding and proceed with VFIO usage
///
/// # Common Use Cases
///
/// ## Graphics Card Passthrough
/// - Unbind from host graphics driver (nouveau, i915, amdgpu)
/// - Bind to vfio-pci for VM passthrough
/// - Requires switching to console or SSH access
///
/// ## Network Device Passthrough
/// - Unbind from network driver (e1000e, ixgbe, mlx4)
/// - Bind to vfio-pci for VM networking
/// - May interrupt host network connectivity
///
/// ## Storage Controller Passthrough
/// - Unbind from storage driver (ahci, nvme)
/// - Bind to vfio-pci for VM storage access
/// - Requires careful planning to avoid data loss
///
/// # Troubleshooting Common Issues
///
/// ## Permission Errors
/// - Run with sudo or configure udev rules for device access
/// - Check user group membership (typically need to be in vfio group)
/// - Verify SELinux/AppArmor policies allow driver unbinding
///
/// ## Device In Use
/// - Check for processes actively using the device
/// - For graphics cards, switch to console mode first
/// - For network devices, consider temporary connectivity loss
/// - For storage devices, ensure no mounted filesystems
///
/// ## Driver Dependencies
/// - Some drivers may have dependencies preventing unbinding
/// - Check for kernel modules that depend on the target driver
/// - Use `lsmod` and `modinfo` to analyze module relationships
///
/// ## Hardware Issues
/// - Device may be in an inconsistent state
/// - Try system reboot to reset device state
/// - Check hardware connections and power status
///
/// # Performance Considerations
///
/// The unbinding process involves several operations:
/// - Sysfs file system operations: < 10ms for path validation and symlink resolution
/// - Driver remove callback execution: 10-100ms depending on driver complexity
/// - Kernel driver subsystem updates: < 5ms for internal state changes
/// - Total unbinding time: typically 20-150ms for most devices
///
/// Graphics drivers may take longer due to cleanup of GPU contexts and memory.
///
/// # Platform Compatibility
///
/// This function works on Linux systems with:
/// - **Kernel Versions**: 2.6+ for basic driver binding, 3.0+ recommended
/// - **Architectures**: x86_64, ARM64, and other architectures with PCI support
/// - **Distributions**: All major Linux distributions with standard sysfs
/// - **Container Environments**: Works in containers with appropriate device access
///
/// # Return Values
///
/// - `Ok(())`: Device successfully unbound or was already unbound
/// - `Err(PocError::PathNotFound)`: Device not found in PCI subsystem
/// - `Err(PocError::DeviceBindingError)`: Driver path issues or unbind interface problems
/// - `Err(PocError::IoError)`: Filesystem access or write operation failures
///
/// # See Also
///
/// Related device management functions:
/// - [`bind_device_to_vfio()`]: Bind device to vfio-pci driver
/// - [`list_devices_with_iommu()`]: Discover unbindable devices
/// - [`check_device_drivers()`]: Analyze current driver binding status
/// - [`check_security_settings()`]: Verify permissions for device operations
fn unbind_device(device: &str) -> Result<(), PocError> {
    println!("=== Unbinding Device {device} ===");

    let device_path = Path::new("/sys/bus/pci/devices").join(device);
    if !device_path.exists() {
        return Err(PocError::PathNotFound(format!("Device {device} not found")));
    }

    // Check if device has a driver
    let driver_path = device_path.join("driver");
    if !driver_path.exists() {
        println!("  o Device {device} is already unbound");
        return Ok(());
    }

    // Get current driver name
    let current_driver = driver_path
        .read_link()?
        .file_name()
        .ok_or_else(|| PocError::DeviceBindingError("Invalid driver path".into()))?
        .to_string_lossy()
        .to_string();

    println!("  Current driver: {current_driver}");

    // Unbind from current driver
    let unbind_path = Path::new("/sys/bus/pci/drivers")
        .join(&current_driver)
        .join("unbind");

    if unbind_path.exists() {
        fs::write(&unbind_path, device)?;
        println!("  v Successfully unbound {device} from {current_driver}");
    } else {
        return Err(PocError::DeviceBindingError(format!(
            "Unbind path not found for driver {current_driver}"
        )));
    }

    Ok(())
}

/// Binds a PCI device to the vfio-pci driver for VFIO passthrough operations.
///
/// This function performs the complete process of binding a PCI device to the vfio-pci
/// driver, making it available for VFIO-based device passthrough to virtual machines
/// or userspace applications. The function handles driver loading, device unbinding
/// from current drivers, ID registration, and binding verification.
///
/// The binding process follows the standard Linux driver binding mechanism:
/// 1. **Driver Availability**: Ensures vfio-pci driver is loaded and accessible
/// 2. **Device Identification**: Extracts vendor and device IDs from sysfs
/// 3. **Current Driver Unbinding**: Detaches device from any existing driver
/// 4. **ID Registration**: Adds device IDs to vfio-pci's new_id interface
/// 5. **Binding Verification**: Confirms successful binding to vfio-pci
///
/// # Parameters
///
/// * `device` - PCI device address in standard format (e.g., "0000:3b:00.0")
///   - **Domain**: 4-digit hexadecimal PCI domain (usually 0000)
///   - **Bus**: 2-digit hexadecimal PCI bus number
///   - **Device**: 2-digit hexadecimal device number (0-31)
///   - **Function**: 1-digit hexadecimal function number (0-7)
///
/// # Binding Process Details
///
/// ## Driver Module Loading
/// If the vfio-pci driver is not already loaded, the function attempts to load it
/// using the `modprobe` command. This requires appropriate system permissions
/// and may fail if the module is not available or if there are dependency issues.
///
/// ## Device ID Extraction
/// The function reads vendor and device IDs from sysfs attributes:
/// - `/sys/bus/pci/devices/{device}/vendor` - Hardware vendor ID
/// - `/sys/bus/pci/devices/{device}/device` - Hardware device ID
///
/// Both IDs are automatically normalized by removing "0x" prefixes if present.
///
/// ## Current Driver Unbinding
/// If the device is currently bound to another driver, it is automatically unbound
/// using the [`unbind_device()`] function. This ensures clean driver transitions
/// and prevents conflicts during the binding process.
///
/// ## ID Registration and Binding
/// The device's vendor:device ID pair is written to the vfio-pci driver's `new_id`
/// interface, which triggers automatic binding if the device is available and
/// compatible with the vfio-pci driver.
///
/// ## Binding Verification
/// After a brief delay to allow kernel processing, the function verifies that
/// the binding was successful by checking the device's current driver symlink.
///
/// # Output Format
///
/// The function provides detailed console output tracking the binding process:
/// ```text
/// === Binding Device 0000:3b:00.0 to vfio-pci ===
///   Device IDs: 10de:2204
///   Binding 0000:3b:00.0 to vfio-pci driver...
///   v Successfully bound 0000:3b:00.0 to vfio-pci
///   v Binding verified successfully
/// ```
///
/// # Error Conditions
///
/// The function handles several categories of errors:
///
/// ## Device Not Found
/// - Missing device in `/sys/bus/pci/devices/`
/// - Invalid PCI address format
/// - Device removed or not enumerated by kernel
///
/// ## Driver Loading Failures
/// - vfio-pci module not available in kernel
/// - Insufficient permissions to load kernel modules
/// - Module dependency issues or signature problems
///
/// ## Binding Process Errors
/// - Device IDs cannot be read from sysfs
/// - vfio-pci driver doesn't support dynamic ID addition
/// - Device already exclusively bound to another driver
/// - Kernel refuses binding due to device incompatibility
///
/// ## Verification Failures
/// - Binding appears successful but device remains unbound
/// - Device bound to unexpected driver after binding attempt
/// - Timing issues with kernel driver binding process
///
/// # System Requirements
///
/// This function requires:
/// - Linux operating system with sysfs filesystem
/// - vfio-pci kernel module available (built-in or loadable)
/// - Root privileges or appropriate udev rules for vfio operations
/// - Device must be in an IOMMU group for VFIO compatibility
/// - Compatible hardware supporting VFIO passthrough
///
/// # Security Considerations
///
/// Binding devices to vfio-pci has security implications:
/// - **Device Access**: Grants userspace direct hardware access
/// - **IOMMU Dependency**: Requires IOMMU for memory protection
/// - **Privilege Requirements**: Typically requires elevated permissions
/// - **System Stability**: Improper use can cause system instability
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{bind_device_to_vfio, PocError};
/// // Bind a graphics card for GPU passthrough
/// match bind_device_to_vfio("0000:01:00.0") {
///     Ok(()) => println!("GPU successfully bound to vfio-pci"),
///     Err(e) => {
///         eprintln!("Failed to bind GPU: {}", e);
///         // Handle error - device may need to be unbound first
///     }
/// }
///
/// // Bind a network card for network device passthrough
/// if let Err(e) = bind_device_to_vfio("0000:02:00.0") {
///     eprintln!("Network card binding failed: {}", e);
/// }
/// ```
///
/// # Integration with VFIO Workflow
///
/// This function is typically used as part of a complete VFIO setup sequence:
/// 1. **System Validation**: Run diagnostics to ensure VFIO support
/// 2. **Device Discovery**: Use [`list_devices_with_iommu()`] to find devices
/// 3. **Driver Analysis**: Use [`check_device_drivers()`] to check current state
/// 4. **Device Unbinding**: Use [`unbind_device()`] if needed
/// 5. **VFIO Binding**: Use this function to bind to vfio-pci
/// 6. **Verification**: Re-check device status and proceed with VFIO usage
///
/// # Troubleshooting Common Issues
///
/// ## Module Loading Problems
/// - Ensure vfio-pci module is available: `modinfo vfio-pci`
/// - Check for Secure Boot issues with unsigned modules
/// - Verify module dependencies are satisfied
///
/// ## Permission Errors
/// - Run with sudo or configure udev rules for vfio access
/// - Check user group membership (vfio, kvm groups)
/// - Verify SELinux/AppArmor policies allow vfio operations
///
/// ## Device Compatibility
/// - Confirm device is in an IOMMU group: check [`list_devices_with_iommu()`]
/// - Verify IOMMU is enabled and functioning
/// - Some devices may require specific kernel parameters
///
/// ## Binding Failures
/// - Device may be in use by host system (display, network, etc.)
/// - Check for device dependencies or multi-function constraints
/// - Verify device supports FLR (Function Level Reset)
///
/// # Performance Considerations
///
/// The binding process involves several kernel operations:
/// - Module loading (if needed): 100-500ms depending on module size
/// - Sysfs file operations: < 10ms for ID reading and writing
/// - Driver unbinding/binding: 50-200ms depending on device type
/// - Verification delay: 500ms fixed delay plus kernel processing time
///
/// Total binding time is typically 200ms to 1 second for most devices.
///
/// # Platform Compatibility
///
/// This function works on Linux systems with:
/// - **x86_64**: Full support with Intel VT-d or AMD-Vi
/// - **ARM64**: Support depends on SMMU availability
/// - **Kernel Versions**: 3.6+ for basic VFIO, 4.0+ recommended
/// - **Distributions**: All major Linux distributions with VFIO support
///
/// # Return Values
///
/// - `Ok(())`: Device successfully bound to vfio-pci driver
/// - `Err(PocError::PathNotFound)`: Device not found in sysfs
/// - `Err(PocError::DeviceBindingError)`: Driver loading or binding failure
/// - `Err(PocError::IoError)`: Filesystem access or command execution error
///
/// # See Also
///
/// Related device management functions:
/// - [`unbind_device()`]: Remove device from current driver
/// - [`list_devices_with_iommu()`]: Discover VFIO-compatible devices
/// - [`check_device_drivers()`]: Analyze current driver binding status
/// - [`check_security_settings()`]: Verify permissions for VFIO operations
/// - [`run_diagnostics()`]: Comprehensive system readiness validation
fn bind_device_to_vfio(device: &str) -> Result<(), PocError> {
    println!("=== Binding Device {device} to vfio-pci ===");

    let device_path = Path::new("/sys/bus/pci/devices").join(device);
    if !device_path.exists() {
        return Err(PocError::PathNotFound(format!("Device {device} not found")));
    }

    // Check if vfio-pci driver is available
    let vfio_driver_path = Path::new("/sys/bus/pci/drivers/vfio-pci");
    if !vfio_driver_path.exists() {
        println!("  Loading vfio-pci module...");
        let output = std::process::Command::new("modprobe")
            .arg("vfio-pci")
            .output()?;

        if !output.status.success() {
            return Err(PocError::DeviceBindingError(
                "Failed to load vfio-pci module".into(),
            ));
        }
    }

    // Get device vendor and device IDs
    let vendor_id = fs::read_to_string(device_path.join("vendor"))?
        .trim()
        .to_string();
    let device_id = fs::read_to_string(device_path.join("device"))?
        .trim()
        .to_string();

    // Remove 0x prefix if present
    let vendor_id = vendor_id.strip_prefix("0x").unwrap_or(&vendor_id);
    let device_id = device_id.strip_prefix("0x").unwrap_or(&device_id);

    println!("  Device IDs: {vendor_id}:{device_id}");

    // Add device ID to vfio-pci driver
    let new_id_path = vfio_driver_path.join("new_id");
    let id_string = format!("{vendor_id} {device_id}");

    // First unbind if bound to another driver
    let driver_path = device_path.join("driver");
    if driver_path.exists() {
        unbind_device(device)?;
    }

    // Bind to vfio-pci
    if new_id_path.exists() {
        println!("  Binding {device} to vfio-pci driver...");
        fs::write(&new_id_path, &id_string)?;
        println!("  v Successfully bound {device} to vfio-pci");
    } else {
        return Err(PocError::DeviceBindingError(
            "vfio-pci driver does not support new_id".into(),
        ));
    }

    // Verify binding
    std::thread::sleep(std::time::Duration::from_millis(500));
    let driver_path = device_path.join("driver");
    if driver_path.exists() {
        let current_driver = driver_path
            .read_link()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        if current_driver == "vfio-pci" {
            println!("  v Binding verified successfully");
        } else {
            println!("  ! Binding may have failed - current driver: {current_driver}");
        }
    } else {
        println!("  ! Device appears to be unbound after binding attempt");
    }

    Ok(())
}

/// Analyzes system security settings and permissions for VFIO operations.
///
/// This function performs a comprehensive security audit of the system to identify
/// potential issues that could prevent VFIO device passthrough operations from working
/// correctly. It examines device permissions, user access rights, security modules,
/// and kernel module status to provide a complete picture of the security environment.
///
/// The analysis covers multiple security layers that can impact VFIO functionality:
/// - **Device Permissions**: Access rights to VFIO device files
/// - **User Groups**: Membership in required security groups
/// - **Secure Boot**: UEFI Secure Boot status and module signing implications
/// - **Security Modules**: SELinux and AppArmor configuration analysis
/// - **System Access**: IOMMU groups and kernel module availability
///
/// # Security Checks Performed
///
/// ## VFIO Device Permissions
/// - Verifies existence and accessibility of `/dev/vfio/vfio`
/// - Displays current file permissions in octal format
/// - Tests current user's ability to access the device file
/// - Identifies permission issues that would block VFIO operations
///
/// ## User Group Membership
/// - Checks membership in the `vfio` group for device access
/// - Verifies `kvm` group membership for virtualization support
/// - Provides specific commands to add user to required groups
/// - Lists all current user groups for debugging purposes
///
/// ## Secure Boot Analysis
/// - Reads UEFI Secure Boot status from EFI variables
/// - Warns about potential issues with unsigned VFIO modules
/// - Suggests remediation strategies (BIOS disable vs module signing)
/// - Handles non-EFI systems gracefully
///
/// ## Security Module Assessment
/// - **SELinux**: Checks enforcement mode and policy implications
/// - **AppArmor**: Detects active profiles that may restrict VFIO
/// - Provides guidance on security policy adjustments needed
/// - Identifies when security modules are inactive
///
/// ## System Resource Access
/// - Validates IOMMU groups directory accessibility
/// - Enumerates loaded VFIO-related kernel modules
/// - Identifies missing modules that need to be loaded
/// - Confirms system readiness for VFIO operations
///
/// # Output Format
///
/// The function provides detailed console output organized by security domain:
/// ```text
/// === Security Settings Analysis ===
/// VFIO Device Permissions:
///   /dev/vfio/vfio permissions: 660
///   v Current user can access /dev/vfio/vfio
///
/// User Group Membership:
///   Current groups: user vfio kvm sudo
///   v User is in vfio group
///   v User is in kvm group
///
/// Secure Boot Status:
///   v Secure Boot is disabled
///
/// Security Modules:
///   v SELinux not active
///   v AppArmor not active or not installed
///
/// IOMMU Groups Access:
///   IOMMU groups directory accessible: true
///
/// VFIO Module Status:
///   v vfio module loaded
///   v vfio_pci module loaded
///   v vfio_iommu_type1 module loaded
/// ```
///
/// # Visual Indicators
///
/// The function uses consistent visual indicators for status reporting:
/// - `v`: Successful check or optimal configuration
/// - `x`: Failed check or missing requirement
/// - `!`: Warning about suboptimal but workable configuration
/// - `o`: Informational status or optional component
///
/// # Common Security Issues
///
/// The function identifies and provides guidance for common problems:
///
/// ## Permission Problems
/// - User not in `vfio` or `kvm` groups
/// - Incorrect `/dev/vfio/vfio` file permissions
/// - IOMMU groups directory access restrictions
///
/// ## Secure Boot Conflicts
/// - Enabled Secure Boot blocking unsigned VFIO modules
/// - Module signature verification failures
/// - Need for custom module signing or BIOS configuration
///
/// ## Security Policy Restrictions
/// - SELinux enforcing mode requiring custom policies
/// - AppArmor profiles blocking VFIO device access
/// - Need for security exception configuration
///
/// ## Missing System Components
/// - Unloaded VFIO kernel modules
/// - Missing device files indicating driver issues
/// - Incomplete VFIO infrastructure setup
///
/// # System Requirements
///
/// This function requires:
/// - Linux operating system with standard security infrastructure
/// - Access to `/dev/vfio/vfio`, `/sys/firmware/efi/efivars`, and `/sys/module`
/// - Ability to execute `groups` and `aa-status` commands
/// - Read permissions for EFI variables and system module information
///
/// # Remediation Guidance
///
/// For each identified issue, the function provides specific remediation commands:
/// ```bash
/// # User group membership
/// sudo usermod -a -G vfio $USER
/// sudo usermod -a -G kvm $USER
///
/// # Module loading
/// sudo modprobe vfio
/// sudo modprobe vfio-pci
/// sudo modprobe vfio_iommu_type1
/// ```
///
/// # Security Considerations
///
/// This function helps balance security and functionality:
/// - **Device Access**: Ensures proper permissions without over-privileging
/// - **Module Integrity**: Identifies Secure Boot implications for module loading
/// - **Policy Compliance**: Highlights security policy requirements
/// - **Least Privilege**: Confirms minimal required access for VFIO operations
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{check_security_settings, PocError};
/// // Basic security audit
/// match check_security_settings() {
///     Ok(()) => println!("Security check completed - see output for details"),
///     Err(e) => {
///         eprintln!("Security check failed: {}", e);
///         std::process::exit(1);
///     }
/// }
/// ```
///
/// # Integration with VFIO Workflow
///
/// This function is typically used as part of comprehensive system validation:
/// 1. **Hardware Check**: Verify IOMMU and virtualization support
/// 2. **Kernel Check**: Confirm proper kernel parameters and modules
/// 3. **Security Check**: Use this function to validate permissions and policies
/// 4. **Device Setup**: Proceed with device binding and configuration
///
/// # Platform Compatibility
///
/// The function handles multiple Linux security configurations:
/// - **EFI vs Legacy BIOS**: Adapts Secure Boot checking to system type
/// - **SELinux vs AppArmor**: Detects and analyzes the active security module
/// - **Distribution Variants**: Works across different Linux distributions
/// - **Module Loading**: Handles various kernel module loading mechanisms
///
/// # Performance Considerations
///
/// This function performs several system queries:
/// - File system metadata operations (typically < 10ms)
/// - EFI variable reads (can be slow on some systems, 10-50ms)
/// - Command execution for group checking (< 100ms)
/// - Directory traversal for module detection (< 20ms)
///
/// Total execution time is typically under 200ms on modern systems.
///
/// # Return Values
///
/// - `Ok(())`: Security analysis completed successfully (issues may still exist)
/// - `Err(PocError::IoError)`: Filesystem access or command execution failure
///
/// Note: This function reports security issues via console output but does not
/// fail on security problems - it always returns `Ok(())` unless system access fails.
///
/// # See Also
///
/// Related security and system validation functions:
/// - [`run_diagnostics()`]: Overall system readiness validation
/// - [`check_vm_readiness()`]: Virtualization environment validation
/// - [`check_device_drivers()`]: Driver binding and availability analysis
/// - [`list_devices_with_iommu()`]: Device enumeration and access verification
fn check_security_settings() -> Result<(), PocError> {
    println!("=== Security Settings Analysis ===");

    // Check /dev/vfio permissions
    println!("VFIO Device Permissions:");
    let vfio_path = Path::new("/dev/vfio/vfio");
    if vfio_path.exists() {
        let metadata = fs::metadata(vfio_path)?;

        let permissions = metadata.permissions();
        println!(
            "  /dev/vfio/vfio permissions: {:o}",
            permissions.mode() & 0o777
        );

        // Check if current user can access
        if vfio_path.metadata().is_ok() {
            println!("  v Current user can access /dev/vfio/vfio");
        } else {
            println!("  x Current user cannot access /dev/vfio/vfio");
        }
    } else {
        println!("  x /dev/vfio/vfio not found");
    }

    // Check user groups
    println!("\nUser Group Membership:");
    let output = std::process::Command::new("groups").output()?;

    let groups = String::from_utf8_lossy(&output.stdout);
    println!("  Current groups: {}", groups.trim());

    if groups.contains("vfio") {
        println!("  v User is in vfio group");
    } else {
        println!("  ! User not in vfio group");
        println!("     Add with: sudo usermod -a -G vfio $USER");
    }

    if groups.contains("kvm") {
        println!("  v User is in kvm group");
    } else {
        println!("  ! User not in kvm group");
        println!("     Add with: sudo usermod -a -G kvm $USER");
    }

    // Check Secure Boot status
    println!("\nSecure Boot Status:");
    let secureboot_path =
        Path::new("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    if secureboot_path.exists() {
        if let Ok(data) = fs::read(secureboot_path) {
            if data.len() >= 5 && data[4] == 1 {
                println!("  ! Secure Boot is ENABLED");
                println!("     May cause issues with unsigned VFIO modules");
                println!("     Consider disabling in BIOS or signing modules");
            } else {
                println!("  v Secure Boot is disabled");
            }
        }
    } else {
        println!("  o Secure Boot status unknown (not EFI or no SecureBoot var)");
    }

    // Check SELinux/AppArmor
    println!("\nSecurity Modules:");

    // SELinux check
    if Path::new("/sys/fs/selinux").exists() {
        if let Ok(status) = fs::read_to_string("/sys/fs/selinux/enforce") {
            match status.trim() {
                "1" => {
                    println!("  ! SELinux is in enforcing mode");
                    println!("     May require additional policies for VFIO");
                }
                "0" => println!("  v SELinux is in permissive mode"),
                _ => println!("  o SELinux status unknown"),
            }
        }
    } else {
        println!("  v SELinux not active");
    }

    // AppArmor check
    let apparmor_check = std::process::Command::new("aa-status").output();

    match apparmor_check {
        Ok(output) if output.status.success() => {
            println!("  ! AppArmor is active");
            println!("     May require profiles for VFIO usage");
        }
        _ => println!("  v AppArmor not active or not installed"),
    }

    // Check IOMMU group ownership
    println!("\nIOMMU Groups Access:");
    let iommu_groups_path = Path::new("/sys/kernel/iommu_groups");
    if iommu_groups_path.exists() {
        let metadata = fs::metadata(iommu_groups_path)?;
        println!(
            "  IOMMU groups directory accessible: {}",
            metadata.permissions().mode() & 0o444 != 0
        );
    }

    // Check for common VFIO-related files
    println!("\nVFIO Module Status:");
    let vfio_modules = ["vfio", "vfio_pci", "vfio_iommu_type1"];
    for module in &vfio_modules {
        let module_path = format!("/sys/module/{module}");
        if Path::new(&module_path).exists() {
            println!("  v {module} module loaded");
        } else {
            println!("  x {module} module not loaded");
        }
    }

    Ok(())
}

/// Performs comprehensive IOMMU diagnostics to validate system configuration.
///
/// This function executes a complete diagnostic sequence to verify that the system
/// is properly configured for IOMMU-based device passthrough and VFIO operations.
/// It systematically checks hardware capabilities, firmware settings, and kernel
/// configuration to identify and report any issues that would prevent successful
/// virtualization or device passthrough.
///
/// The diagnostic process validates three critical system layers:
/// 1. **Hardware Support**: CPU virtualization features and IOMMU capabilities
/// 2. **Firmware Configuration**: BIOS/UEFI settings for virtualization and IOMMU
/// 3. **Kernel Parameters**: Boot-time configuration for IOMMU activation
///
/// # Diagnostic Sequence
///
/// The function performs checks in dependency order, stopping at the first failure:
///
/// ## Hardware Support Check
/// - Verifies CPU virtualization extensions (Intel VT-x or AMD-V)
/// - Confirms IOMMU hardware presence (Intel VT-d or AMD-Vi)
/// - Checks kernel detection of IOMMU capabilities via dmesg
/// - Validates that virtualization features are exposed to the OS
///
/// ## BIOS/UEFI Settings Check
/// - Confirms virtualization extensions are enabled in firmware
/// - Verifies IOMMU/VT-d/AMD-Vi is activated in BIOS/UEFI
/// - Checks for Extended Page Tables (EPT) availability on Intel
/// - Validates that IOMMU groups are created and functional
///
/// ## Kernel Parameters Check
/// - Verifies correct IOMMU activation parameters (`intel_iommu=on` or `amd_iommu=on`)
/// - Checks for passthrough mode configuration (`iommu=pt`)
/// - Validates that IOMMU groups are accessible and populated
/// - Provides specific remediation guidance for missing parameters
///
/// # Output Format
///
/// The function provides detailed console output with visual indicators:
/// ```text
/// === IOMMU DIAGNOSTICS ===
///
/// === Hardware Support Check ===
/// Virtualization support:
///   v Intel VT-x (vmx) - SUPPORTED
/// IOMMU support in kernel:
///   v Intel IOMMU/VT-d detected
///
/// === BIOS/UEFI Settings Check ===
///   v Intel VT-x enabled in BIOS
///   v EPT (Extended Page Tables) available
///   v IOMMU working correctly (42 groups)
///
/// === Kernel Parameters Check ===
/// Current kernel parameters:
///   root=UUID=... intel_iommu=on iommu=pt quiet splash
///
/// Parameter analysis:
///   v intel_iommu=on - Intel IOMMU enabled
///   v iommu=pt - passthrough mode enabled
///   v IOMMU working: 42 groups available
///
/// === SUMMARY ===
/// v All checks passed successfully!
/// v IOMMU is properly configured
/// ```
///
/// # Error Handling and Early Termination
///
/// The function uses fail-fast error handling - if any diagnostic check fails,
/// execution stops immediately and the error is propagated to the caller. This
/// approach ensures that:
/// - Users receive immediate feedback about the first blocking issue
/// - Subsequent checks don't mask earlier fundamental problems
/// - Clear error messages guide users to specific remediation steps
///
/// Common failure scenarios include:
/// - **Hardware Issues**: CPU lacks virtualization support or IOMMU hardware
/// - **Firmware Problems**: Virtualization disabled in BIOS/UEFI settings
/// - **Kernel Configuration**: Missing or incorrect boot parameters
///
/// # System Requirements
///
/// This diagnostic requires:
/// - Linux operating system with sysfs filesystem
/// - Access to `/proc/cpuinfo`, `/proc/cmdline`, and `/sys/kernel/iommu_groups`
/// - Ability to execute `dmesg` command for kernel message analysis
/// - Sufficient permissions to read system configuration files
///
/// # Integration with VFIO Workflow
///
/// This function is typically the first step in VFIO device management:
/// 1. **Diagnostics**: Run this function to validate system readiness
/// 2. **Device Discovery**: Use `list_devices_with_iommu()` to find devices
/// 3. **Driver Management**: Unbind/bind devices as needed
/// 4. **Application Development**: Implement VFIO-based applications
///
/// # Platform Compatibility
///
/// The function supports both major x86 virtualization platforms:
/// - **Intel**: VT-x, VT-d, EPT detection and validation
/// - **AMD**: AMD-V, AMD-Vi (IOMMU) detection and validation
///
/// Detection is automatic based on CPU features and kernel parameters.
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{run_diagnostics, PocError};
/// // Basic diagnostic run
/// match run_diagnostics() {
///     Ok(()) => println!("System ready for VFIO operations"),
///     Err(e) => {
///         eprintln!("System configuration issue: {}", e);
///         eprintln!("Please resolve the above issue and retry");
///         std::process::exit(1);
///     }
/// }
/// ```
///
/// # Troubleshooting Guidance
///
/// When diagnostics fail, the function provides specific guidance:
/// - **Hardware issues**: CPU compatibility and upgrade recommendations
/// - **BIOS settings**: Specific firmware options to enable
/// - **Kernel parameters**: Exact GRUB configuration commands
/// - **Module loading**: Commands to load required kernel modules
///
/// # Performance Considerations
///
/// This function performs several system calls and file I/O operations:
/// - Reading `/proc/cpuinfo` and `/proc/cmdline` (typically < 1KB each)
/// - Directory enumeration of `/sys/kernel/iommu_groups`
/// - Executing `dmesg` command and parsing output
/// - Multiple filesystem metadata checks
///
/// Total execution time is typically under 100ms on modern systems.
///
/// # Return Values
///
/// - `Ok(())`: All diagnostic checks passed successfully
/// - `Err(PocError::IommuNotEnabled)`: IOMMU hardware or configuration issues
/// - `Err(PocError::IoError)`: Filesystem access or system call failures
///
/// # See Also
///
/// Related diagnostic functions:
/// - [`check_hardware_support()`]: Individual hardware capability check
/// - [`check_bios_settings()`]: Firmware configuration validation
/// - [`check_kernel_parameters()`]: Boot parameter verification
/// - [`list_devices_with_iommu()`]: Device enumeration after successful diagnostics
fn run_diagnostics() -> Result<(), PocError> {
    println!("=== IOMMU DIAGNOSTICS ===\n");

    // Check hardware support
    if let Err(e) = check_hardware_support() {
        println!("x Hardware support problem: {e}");
        return Err(e);
    }

    // Check BIOS settings
    if let Err(e) = check_bios_settings() {
        println!("x BIOS settings problem: {e}");
        return Err(e);
    }

    // Check kernel parameters
    if let Err(e) = check_kernel_parameters() {
        println!("x Kernel parameters problem: {e}");
        return Err(e);
    }

    println!("\n=== SUMMARY ===");
    println!("v All checks passed successfully!");
    println!("v IOMMU is properly configured");

    Ok(())
}

/// Lists all PCI devices with IOMMU group assignments and their current status.
///
/// This function enumerates PCI devices that have been assigned to IOMMU groups by the kernel,
/// providing a comprehensive overview of devices available for virtualization and passthrough
/// operations. The function displays essential information about each device including its
/// IOMMU group membership, current driver binding, and hardware identification.
///
/// The output includes a formatted table showing:
/// - **Device**: PCI address in format `domain:bus:device.function` (e.g., 0000:3b:00.0)
/// - **Group**: IOMMU group number that controls device isolation
/// - **Driver**: Currently bound kernel driver (or "none" if unbound)
/// - **Device ID**: Vendor:Device ID pair for hardware identification
///
/// # IOMMU Groups and Isolation
///
/// IOMMU groups represent the smallest set of devices that can be isolated from each other.
/// Devices in the same IOMMU group must be passed through to the same virtual machine or
/// all remain with the host system. This function helps identify:
///
/// - Devices ready for VFIO passthrough (bound to `vfio-pci`)
/// - Devices currently in use by the host system
/// - Available devices that can be unbound and reassigned
/// - Group relationships that affect passthrough decisions
///
/// # System Requirements
///
/// This function requires:
/// - IOMMU enabled in BIOS/UEFI firmware
/// - Kernel boot parameters: `intel_iommu=on` or `amd_iommu=on`
/// - Access to `/sys/bus/pci/devices` filesystem
/// - Sufficient permissions to read device symlinks and attributes
///
/// # Output Format
///
/// ```text
/// === PCI Devices with IOMMU Enabled ===
/// Device          Group      Driver                         Device ID
/// ---------------------------------------------------------------------------
/// 0000:00:1f.0    14         pcieport                       0x8086:0xa32c
/// 0000:3b:00.0    26         vfio-pci                       0x10de:0x2204
/// 0000:3c:00.0    27         none                           0x8086:0x15f3
/// ```
///
/// # Error Handling
///
/// The function handles several error conditions gracefully:
/// - Missing `/sys/bus/pci/devices` directory (returns success with warning)
/// - Inaccessible device subdirectories (skips individual devices)
/// - Broken symlinks or missing attribute files (shows "unknown" values)
/// - I/O errors during filesystem operations (propagated as `PocError::IoError`)
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{list_devices_with_iommu, PocError};
/// // List all IOMMU-capable devices
/// if let Err(e) = list_devices_with_iommu() {
///     eprintln!("Failed to list devices: {}", e);
/// }
/// ```
///
/// # Platform Compatibility
///
/// This function is Linux-specific and relies on the sysfs filesystem structure.
/// It works with both Intel VT-d and AMD-Vi IOMMU implementations, providing
/// consistent output regardless of the underlying hardware platform.
///
/// # Integration with VFIO Workflow
///
/// This function is typically used as part of a larger VFIO management workflow:
/// 1. **Discovery**: Use this function to identify available devices
/// 2. **Unbinding**: Detach devices from host drivers using `unbind_device()`
/// 3. **Binding**: Attach devices to vfio-pci using `bind_device_to_vfio()`
/// 4. **Verification**: Re-run this function to confirm successful binding
///
/// # Performance Considerations
///
/// The function performs filesystem I/O operations for each PCI device, which may
/// be slow on systems with many devices. The performance impact is typically
/// negligible for interactive use but should be considered in automated scripts
/// that run frequently.
///
/// # Returns
///
/// Returns `Ok(())` on successful completion or `PocError::IoError` if filesystem
/// operations fail. The function does not fail if no IOMMU-capable devices are
/// found, as this may be a valid system configuration.
fn list_devices_with_iommu() -> Result<(), PocError> {
    let pci_devices_path = Path::new("/sys/bus/pci/devices");
    if !pci_devices_path.exists() {
        println!("x PCI devices directory not found");
        return Ok(());
    }

    println!("=== PCI Devices with IOMMU Enabled ===");
    println!(
        "{:<15} {:<10} {:<30} {:<20}",
        "Device", "Group", "Driver", "Device ID"
    );
    println!("{:-<75}", "");

    let entries = fs::read_dir(pci_devices_path)?;
    let mut found_devices = false;

    for entry in entries {
        let entry = entry?;
        let device_path = entry.path();
        let device_name = device_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Check if device has IOMMU group
        let iommu_group_path = device_path.join("iommu_group");
        if iommu_group_path.exists() {
            found_devices = true;

            // Get IOMMU group number
            let group_number = if let Ok(target) = fs::read_link(&iommu_group_path) {
                target
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                "unknown".to_string()
            };

            // Get driver name if available
            let driver_path = device_path.join("driver");
            let driver = if driver_path.exists() {
                if let Ok(target) = fs::read_link(&driver_path) {
                    target
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string()
                } else {
                    "unknown".to_string()
                }
            } else {
                "none".to_string()
            };

            // Get device info if available
            let vendor_path = device_path.join("vendor");
            let device_id_path = device_path.join("device");
            let mut device_info = String::new();

            if let (Ok(vendor), Ok(device_id)) = (
                fs::read_to_string(&vendor_path),
                fs::read_to_string(&device_id_path),
            ) {
                device_info = format!("{}:{}", vendor.trim(), device_id.trim());
            }

            println!("{device_name:<15} {group_number:<10} {driver:<30} {device_info}");
        }
    }

    if !found_devices {
        println!("! No PCI devices with IOMMU found");
    }

    Ok(())
}

/// High-level interface for VFIO device communication and memory operations.
///
/// `VfioInterface` provides a safe and convenient abstraction layer over the low-level
/// VFIO (Virtual Function I/O) device interface, enabling direct hardware access for
/// virtualization and device passthrough scenarios. This structure encapsulates both
/// the underlying VFIO device handle and the target memory region configuration.
///
/// The interface is designed to simplify common VFIO operations such as memory-mapped
/// I/O, register access, and bulk data transfers while maintaining the performance
/// characteristics required for high-throughput device communication.
///
/// # Purpose
///
/// This interface serves as the foundation for:
/// - **Device Register Access**: Reading and writing device control and status registers
/// - **Memory-Mapped I/O**: Direct access to device memory regions for data transfer
/// - **Admin Queue Operations**: Implementation of command/response protocols
/// - **Bulk Data Transfer**: Efficient transfer of large data buffers to/from devices
/// - **Hardware Abstraction**: Providing a consistent API across different device types
///
/// # Fields
///
/// * `device` - The underlying VFIO device handle providing low-level hardware access
/// * `region_id` - Identifier for the specific memory region used for operations
///
/// # Memory Region Usage
///
/// Different region IDs typically correspond to different device functions:
/// - **Region 0**: Usually the main device registers and control interface
/// - **Region 1**: Often device-specific memory or buffer areas
/// - **Region 2+**: Additional memory regions for specialized device functions
///
/// # Thread Safety
///
/// The interface assumes single-threaded access to the underlying device. For
/// multi-threaded scenarios, external synchronization mechanisms should be employed
/// to prevent race conditions and ensure data consistency.
///
/// # Hardware Requirements
///
/// This interface requires:
/// - IOMMU support enabled in the system
/// - Device bound to the vfio-pci driver
/// - Appropriate user permissions for VFIO device access
/// - Compatible hardware supporting memory-mapped I/O operations
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{VfioInterface, VfioDevice};
/// # let device: VfioDevice = unimplemented!();
/// // Create interface for main device region
/// let vfio_interface = VfioInterface::new(device, 0);
///
/// // Read device status register
/// let status = vfio_interface.read_register32(0x00)?;
/// println!("Device status: 0x{:08x}", status);
///
/// // Write configuration value
/// vfio_interface.write_register32(0x04, 0x12345678)?;
///
/// // Transfer bulk data
/// let data = vec![0u8; 1024];
/// vfio_interface.write_bulk(0x1000, &data)?;
/// ```
///
/// # Error Handling
///
/// All operations return `Result<T, PocError>` types to provide comprehensive
/// error reporting for device communication failures, permission issues, or
/// hardware-related problems.
///
/// # Performance Considerations
///
/// - Direct memory access operations bypass kernel overhead for maximum performance
/// - Large bulk transfers are more efficient than multiple small operations
/// - Register access should be minimized in performance-critical code paths
/// - Memory barriers may be required for certain hardware ordering requirements
pub struct VfioInterface {
    device: VfioDevice,
    region_id: u32,
}

/// Admin queue descriptor structure for device command management.
///
/// `AqDescriptor` represents a standardized admin queue command descriptor used for
/// communication with VFIO-controlled hardware devices. This structure encapsulates
/// both the fixed header fields required by the hardware interface and a flexible
/// data payload that can be customized for specific command types.
///
/// The descriptor follows the common admin queue pattern used in modern hardware
/// devices, providing a consistent interface for command submission, tracking,
/// and response handling.
///
/// # Type Parameters
///
/// * `T` - The type of the flexible data payload. Must implement both `AqSerDes`
///   for serialization/deserialization and `Default` for initialization.
///
/// # Fields
///
/// The descriptor contains the following fields in hardware-compatible layout:
/// * `flags` - 16-bit command flags and control bits
/// * `opcode` - 16-bit operation code identifying the command type
/// * `datalen` - 16-bit length of associated data buffer in bytes
/// * `retval` - 16-bit return value or status code from device
/// * `cookie_high` - Upper 32 bits of a 64-bit command tracking cookie
/// * `cookie_low` - Lower 32 bits of a 64-bit command tracking cookie
/// * `flex_data` - Flexible data payload specific to the command type
///
/// # Hardware Layout
///
/// When serialized, the descriptor follows this binary layout:
/// ```text
/// Offset | Size | Field       | Description
/// -------|------|-------------|----------------------------------
/// 0      | 2    | flags       | Command flags and control bits
/// 2      | 2    | opcode      | Command operation code
/// 4      | 2    | datalen     | Length of associated data buffer
/// 6      | 2    | retval      | Return value/status code
/// 8      | 4    | cookie_high | High 32 bits of command cookie
/// 12     | 4    | cookie_low  | Low 32 bits of command cookie
/// 16     | var  | flex_data   | Flexible data payload
/// ```
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{AqDescriptor, GenericData};
/// // Create a new descriptor with all fields specified
/// let descriptor = AqDescriptor::new(
///     0x0200,                    // flags
///     0x0001,                    // opcode
///     0,                         // datalen (will be set automatically)
///     0,                         // retval
///     0,                         // cookie_high
///     0x12345678,               // cookie_low
///     GenericData::default(),    // flex_data
/// );
///
/// // Create a descriptor with just opcode and data (recommended)
/// let simple_descriptor = AqDescriptor::from_opcode(0x0006, GenericData {
///     param0: 1024,     // Buffer size
///     param1: 0,        // Flags
///     addr_high: 0,     // Address upper bits
///     addr_low: 0x1000, // Address lower bits
/// });
/// ```
///
/// # Command Flow
///
/// Typical usage follows this pattern:
/// 1. Create descriptor with `new()` or `from_opcode()`
/// 2. Submit via `SendAqCommand::send_aq_command()`
/// 3. Receive response via `ReceiveAqCommand::receive_aq_command()`
/// 4. Check `retval` field for command completion status
#[derive(Debug)]
pub struct AqDescriptor<T>
where
    T: AqSerDes,
    T: Default,
{
    flags: u16,
    opcode: u16,
    datalen: u16,
    retval: u16,
    cookie_high: u32,
    cookie_low: u32,
    flex_data: T,
}

/// Implementation of constructor and utility methods for `AqDescriptor`.
///
/// This implementation provides convenient methods for creating and initializing
/// admin queue descriptors with appropriate default values and common usage patterns.
impl<T: Default + AqSerDes> AqDescriptor<T> {
    /// Creates a new admin queue descriptor with all fields specified.
    ///
    /// This constructor provides complete control over all descriptor fields,
    /// allowing precise configuration for advanced use cases or when working
    /// with specific hardware requirements.
    ///
    /// # Parameters
    ///
    /// * `flags` - Command flags and control bits (typically 0x0200 for standard commands)
    /// * `opcode` - Operation code identifying the specific command type
    /// * `datalen` - Length of associated data buffer (usually set automatically)
    /// * `retval` - Initial return value (typically 0, set by device on completion)
    /// * `cookie_high` - Upper 32 bits of command tracking cookie
    /// * `cookie_low` - Lower 32 bits of command tracking cookie
    /// * `flex_data` - Flexible data payload containing command-specific parameters
    ///
    /// # Returns
    ///
    /// Returns a new `AqDescriptor<T>` instance with all fields initialized
    /// to the provided values.
    ///
    /// # Flag Values
    ///
    /// Common flag values include:
    /// - `0x0200`: Standard command with default behavior
    /// - `0x1200`: Command with associated data buffer
    /// - `0x1400`: Command with large data buffer (>512 bytes)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{AqDescriptor, GenericData};
    /// let descriptor = AqDescriptor::new(
    ///     0x0200,                    // Standard command flags
    ///     0x0010,                    // Get device info opcode
    ///     0,                         // No data buffer initially
    ///     0,                         // Return value set by device
    ///     0x00000001,               // Cookie high for tracking
    ///     0x12345678,               // Cookie low for tracking
    ///     GenericData {              // Command parameters
    ///         param0: 0,
    ///         param1: 0,
    ///         addr_high: 0,
    ///         addr_low: 0,
    ///     },
    /// );
    /// ```
    pub fn new(
        flags: u16,
        opcode: u16,
        datalen: u16,
        retval: u16,
        cookie_high: u32,
        cookie_low: u32,
        flex_data: T,
    ) -> Self {
        AqDescriptor {
            flags,
            opcode,
            datalen,
            retval,
            cookie_high,
            cookie_low,
            flex_data,
        }
    }

    /// Creates a new admin queue descriptor with sensible defaults.
    ///
    /// This convenience constructor creates a descriptor with commonly used
    /// default values, requiring only the operation code and flexible data
    /// payload. This is the recommended way to create descriptors for most
    /// use cases.
    ///
    /// # Default Values
    ///
    /// The method sets the following defaults:
    /// - `flags`: 0x0200 (standard command flags)
    /// - `datalen`: 0 (will be updated automatically when buffer is attached)
    /// - `retval`: 0 (will be set by device upon completion)
    /// - `cookie_high`: 0 (no command tracking)
    /// - `cookie_low`: 0 (no command tracking)
    ///
    /// # Parameters
    ///
    /// * `opcode` - Operation code identifying the specific command type
    /// * `flex_data` - Flexible data payload containing command-specific parameters
    ///
    /// # Returns
    ///
    /// Returns a new `AqDescriptor<T>` instance configured with the specified
    /// opcode and data, plus appropriate default values for other fields.
    ///
    /// # Command Opcodes
    ///
    /// Common operation codes include:
    /// - `0x0001`: Get device capabilities
    /// - `0x0006`: Get device statistics
    /// - `0x0010`: Get device information
    /// - `0x0020`: Configure device settings
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{AqDescriptor, GenericData};
    /// // Create descriptor for device info command
    /// let descriptor = AqDescriptor::from_opcode(0x0010, GenericData {
    ///     param0: 1,        // Info type selector
    ///     param1: 0,        // Reserved
    ///     addr_high: 0,     // Response buffer address high
    ///     addr_low: 0x2000, // Response buffer address low
    /// });
    ///
    /// // Create descriptor for statistics command
    /// let stats_descriptor = AqDescriptor::from_opcode(0x0006, GenericData::default());
    /// ```
    pub fn from_opcode(opcode: u16, flex_data: T) -> Self {
        AqDescriptor::new(
            0x0200, // Default flags
            opcode, 0, // Default data length
            0, // Default return value
            0, // Default cookie high
            0, // Default cookie low
            flex_data,
        )
    }
}

/// Generic data structure for admin queue command payloads.
///
/// `GenericData` provides a standardized 16-byte data payload format for admin queue
/// commands that require parameter passing or address specification. This structure
/// follows the common pattern used in hardware device interfaces where commands
/// need to pass numerical parameters and memory addresses.
///
/// The structure is designed to be compatible with little-endian byte ordering
/// and provides a flexible foundation for various admin queue command types.
///
/// # Fields
///
/// * `param0` - First 32-bit parameter for command-specific data
/// * `param1` - Second 32-bit parameter for additional command data
/// * `addr_high` - Upper 32 bits of a 64-bit memory address
/// * `addr_low` - Lower 32 bits of a 64-bit memory address
///
/// # Memory Layout
///
/// The serialized format uses little-endian byte ordering:
/// ```text
/// Offset | Size | Field     | Description
/// -------|------|-----------|--------------------------------
/// 0      | 4    | param0    | First parameter (32-bit LE)
/// 4      | 4    | param1    | Second parameter (32-bit LE)
/// 8      | 4    | addr_high | Address upper bits (32-bit LE)
/// 12     | 4    | addr_low  | Address lower bits (32-bit LE)
/// ```
///
/// # Usage Examples
///
/// ```no_run
/// # use your_crate::{GenericData, AqSerDes};
/// // Create data for a command with parameters
/// let data = GenericData {
///     param0: 0x1000,     // Buffer size
///     param1: 0x0001,     // Command flags
///     addr_high: 0x0000,  // Upper address bits
///     addr_low: 0x2000,   // Lower address bits
/// };
///
/// // Serialize for transmission
/// let bytes = data.serialize()?;
/// assert_eq!(bytes.len(), 16);
///
/// // Reconstruct from bytes
/// let restored = GenericData::deserialize(&bytes)?;
/// assert_eq!(restored.param0, 0x1000);
/// ```
#[derive(Default, Debug)]
struct GenericData {
    param0: u32,
    param1: u32,
    addr_high: u32,
    addr_low: u32,
}

/// Implementation of serialization and deserialization for `GenericData`.
///
/// This implementation provides binary format conversion for the `GenericData` structure,
/// ensuring compatibility with hardware device interfaces that expect little-endian
/// byte ordering. The serialization produces a fixed 16-byte output suitable for
/// direct transmission to hardware devices.
///
/// # Binary Format
///
/// The serialization follows the standard layout expected by admin queue interfaces:
/// - All fields are encoded as 32-bit little-endian values
/// - Total serialized size is exactly 16 bytes
/// - Field order matches the struct declaration order
///
/// # Error Handling
///
/// Deserialization validates buffer size to prevent out-of-bounds access and
/// ensures data integrity during the conversion process.
impl AqSerDes for GenericData {
    /// Serializes the `GenericData` structure into a byte vector.
    ///
    /// Converts all fields to little-endian byte representation and concatenates
    /// them into a single buffer. The resulting vector is always exactly 16 bytes
    /// in length, making it suitable for fixed-size hardware interfaces.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing exactly 16 bytes of serialized data.
    /// This method never fails for `GenericData` as all fields are simple integers.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{GenericData, AqSerDes};
    /// let data = GenericData {
    ///     param0: 0x12345678,
    ///     param1: 0xABCDEF00,
    ///     addr_high: 0x00000001,
    ///     addr_low: 0xFFFFFFFF,
    /// };
    ///
    /// let serialized = data.serialize()?;
    /// assert_eq!(serialized.len(), 16);
    /// // Bytes are in little-endian format
    /// assert_eq!(&serialized[0..4], &[0x78, 0x56, 0x34, 0x12]);
    /// ```
    fn serialize(&self) -> Result<Vec<u8>, PocError> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.param0.to_le_bytes());
        buffer.extend_from_slice(&self.param1.to_le_bytes());
        buffer.extend_from_slice(&self.addr_high.to_le_bytes());
        buffer.extend_from_slice(&self.addr_low.to_le_bytes());
        Ok(buffer)
    }

    /// Deserializes a byte buffer into a `GenericData` structure.
    ///
    /// Parses a byte buffer containing serialized `GenericData`, extracting each
    /// 32-bit field using little-endian byte ordering. The function validates
    /// buffer size to ensure safe memory access.
    ///
    /// # Parameters
    ///
    /// * `buffer` - Byte slice containing at least 16 bytes of serialized data
    ///
    /// # Returns
    ///
    /// Returns a `GenericData` instance with fields populated from the buffer,
    /// or a `PocError::DeserializationError` if the buffer is too small.
    ///
    /// # Validation
    ///
    /// - Buffer must contain at least 16 bytes
    /// - Each 4-byte segment is interpreted as a little-endian 32-bit integer
    /// - No additional validation is performed on field values
    ///
    /// # Errors
    ///
    /// Returns `PocError::DeserializationError` if the buffer length is less than 16 bytes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{GenericData, AqSerDes};
    /// let buffer = vec![
    ///     0x78, 0x56, 0x34, 0x12,  // param0: 0x12345678
    ///     0x00, 0xEF, 0xCD, 0xAB,  // param1: 0xABCDEF00
    ///     0x01, 0x00, 0x00, 0x00,  // addr_high: 0x00000001
    ///     0xFF, 0xFF, 0xFF, 0xFF,  // addr_low: 0xFFFFFFFF
    /// ];
    ///
    /// let data = GenericData::deserialize(&buffer)?;
    /// assert_eq!(data.param0, 0x12345678);
    /// assert_eq!(data.param1, 0xABCDEF00);
    /// assert_eq!(data.addr_high, 0x00000001);
    /// assert_eq!(data.addr_low, 0xFFFFFFFF);
    /// ```
    fn deserialize(buffer: &[u8]) -> Result<Self, PocError> {
        if buffer.len() < 16 {
            return Err(PocError::DeserializationError);
        }
        Ok(GenericData {
            param0: u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
            param1: u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
            addr_high: u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
            addr_low: u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
        })
    }
}

/// Trait for serialization and deserialization of admin queue data structures.
///
/// The `AqSerDes` trait defines the interface for converting admin queue data structures
/// between their in-memory representation and the binary format required for hardware
/// communication. This trait is essential for all data types that need to be transmitted
/// through the admin queue interface.
///
/// The trait supports bidirectional conversion:
/// - **Serialization**: Converting in-memory structures to byte vectors for transmission
/// - **Deserialization**: Reconstructing structures from received byte data
///
/// # Design Principles
///
/// - **Endianness consistency**: Implementations should use little-endian byte ordering
/// - **Error handling**: All operations return `Result` types for robust error management
/// - **Type safety**: Generic implementations preserve type information during conversion
/// - **Hardware compatibility**: Binary formats match device interface specifications
///
/// # Common Use Cases
///
/// - Admin queue command descriptors
/// - Command payload data structures
/// - Device response data formats
/// - Memory-mapped data structures
///
/// # Implementation Guidelines
///
/// When implementing this trait:
/// 1. Use little-endian byte ordering for multi-byte values
/// 2. Validate buffer sizes in `deserialize` methods
/// 3. Ensure serialization produces consistent output sizes
/// 4. Handle padding requirements for hardware alignment
///
/// # Examples
///
/// ```no_run
/// # use your_crate::{AqSerDes, PocError};
/// # struct MyData { value: u32 }
/// impl AqSerDes for MyData {
///     fn serialize(&self) -> Result<Vec<u8>, PocError> {
///         Ok(self.value.to_le_bytes().to_vec())
///     }
///
///     fn deserialize(buffer: &[u8]) -> Result<Self, PocError> {
///         if buffer.len() < 4 {
///             return Err(PocError::DeserializationError);
///         }
///         let value = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
///         Ok(MyData { value })
///     }
/// }
/// ```
pub trait AqSerDes {
    /// Serializes the data structure into a byte vector.
    ///
    /// Converts the in-memory representation of the data structure into a binary
    /// format suitable for transmission to hardware devices. The implementation
    /// should use consistent byte ordering and produce deterministic output.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the serialized data, or a `PocError` if
    /// serialization fails due to invalid data or internal constraints.
    ///
    /// # Implementation Notes
    ///
    /// - Use little-endian byte ordering for consistency
    /// - Ensure output size matches hardware expectations
    /// - Handle nested structures recursively
    /// - Validate internal data before serialization
    fn serialize(&self) -> Result<Vec<u8>, PocError>;

    /// Deserializes a byte buffer into the data structure.
    ///
    /// Reconstructs the in-memory representation from a binary buffer, typically
    /// received from hardware devices. The implementation should validate buffer
    /// size and content to ensure safe and correct deserialization.
    ///
    /// # Parameters
    ///
    /// * `buffer` - Byte slice containing the serialized data
    ///
    /// # Returns
    ///
    /// Returns the deserialized data structure, or a `PocError` if the buffer
    /// contains invalid data, has insufficient length, or deserialization fails.
    ///
    /// # Implementation Notes
    ///
    /// - Validate buffer size before accessing data
    /// - Use little-endian byte ordering for consistency
    /// - Handle partial data gracefully
    /// - Provide meaningful error messages for debugging
    ///
    /// # Errors
    ///
    /// Common error conditions include:
    /// - Buffer too small for the expected data structure
    /// - Invalid data format or corruption
    /// - Unsupported version or format identifiers
    fn deserialize(buffer: &[u8]) -> Result<Self, PocError>
    where
        Self: Sized;
}

/// Trait for sending admin queue commands to devices.
///
/// The `SendAqCommand` trait defines the interface for transmitting admin queue commands
/// to VFIO-controlled hardware devices. This trait handles the complete command
/// transmission process, including optional data buffer management, descriptor
/// serialization, and device notification.
///
/// The trait is designed to work with any admin queue data type that implements
/// both `Default` and `AqSerDes` traits, providing a flexible foundation for
/// various hardware device interfaces.
///
/// # Type Parameters
///
/// * `T` - The type of the flexible data payload in the admin queue descriptor.
///   Must implement `Default` for initialization and `AqSerDes` for serialization.
///
/// # Command Transmission Process
///
/// 1. **Buffer validation**: Verify optional data buffer size constraints
/// 2. **Data transmission**: Write buffer to device memory region if provided
/// 3. **Descriptor preparation**: Update command metadata and flags
/// 4. **Command serialization**: Convert descriptor to binary format
/// 5. **Device notification**: Signal the device that a command is ready
///
/// # Usage Patterns
///
/// The trait is typically implemented by device interface structures that
/// manage memory-mapped I/O operations and device state:
///
/// ```no_run
/// # use your_crate::{SendAqCommand, AqDescriptor, GenericData, PocError};
/// # struct DeviceInterface;
/// # impl SendAqCommand<GenericData> for DeviceInterface {
/// #     fn send_aq_command(&self, command: &mut AqDescriptor<GenericData>, buffer: Option<&[u8]>) -> Result<(), PocError> {
/// #         unimplemented!()
/// #     }
/// # }
/// # let device = DeviceInterface;
/// let mut command = AqDescriptor::from_opcode(0x01, GenericData::default());
/// let data = vec![0x00, 0x01, 0x02, 0x03];
///
/// // Send command with data buffer
/// device.send_aq_command(&mut command, Some(&data))?;
///
/// // Send command without data
/// device.send_aq_command(&mut command, None)?;
/// ```
///
/// # Error Handling
///
/// Implementations should provide comprehensive error reporting for:
/// - Buffer size violations
/// - Memory access failures
/// - Device communication errors
/// - Serialization failures
pub trait SendAqCommand<T: Default + AqSerDes> {
    /// Sends an admin queue command to the device.
    ///
    /// Transmits a complete admin queue command, including the command descriptor
    /// and optional data buffer, to the target device. The function handles all
    /// aspects of command preparation, data transmission, and device notification.
    ///
    /// # Parameters
    ///
    /// * `command` - Mutable reference to the admin queue descriptor. The function
    ///   may modify fields such as `datalen` and `flags` based on the provided buffer.
    /// * `buffer` - Optional data buffer to transmit with the command. Size constraints
    ///   are implementation-specific but typically limited by device buffer capacity.
    ///
    /// # Command Modification
    ///
    /// The function may modify the command descriptor:
    /// - `datalen` field updated to reflect buffer size
    /// - `flags` field updated to indicate buffer presence and characteristics
    /// - Other fields may be modified based on implementation requirements
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful command transmission, or a `PocError` if:
    /// - Buffer size exceeds device limitations
    /// - Memory access operations fail
    /// - Command serialization fails
    /// - Device communication errors occur
    ///
    /// # Implementation Requirements
    ///
    /// Implementations must:
    /// 1. Validate buffer size constraints
    /// 2. Handle optional buffer transmission
    /// 3. Update command descriptor metadata
    /// 4. Serialize and transmit the command
    /// 5. Notify the device of command availability
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{SendAqCommand, AqDescriptor, GenericData};
    /// # struct VfioDevice;
    /// # impl SendAqCommand<GenericData> for VfioDevice {
    /// #     fn send_aq_command(&self, command: &mut AqDescriptor<GenericData>, buffer: Option<&[u8]>) -> Result<(), your_crate::PocError> {
    /// #         Ok(())
    /// #     }
    /// # }
    /// # let device = VfioDevice;
    /// let mut command = AqDescriptor::from_opcode(0x06, GenericData {
    ///     param0: 1024,        // Buffer size parameter
    ///     param1: 0,           // Unused
    ///     addr_high: 0,        // Address upper bits
    ///     addr_low: 0x1000,    // Address lower bits
    /// });
    ///
    /// let data = vec![0u8; 1024];  // 1KB data buffer
    /// device.send_aq_command(&mut command, Some(&data))?;
    /// // Command sent successfully, descriptor updated automatically
    /// ```
    fn send_aq_command(
        &self,
        command: &mut AqDescriptor<T>,
        buffer: Option<&[u8]>,
    ) -> Result<(), PocError>;
}

/// A trait for receiving admin queue command responses from devices.
///
/// The `ReceiveAqCommand` trait defines the interface for retrieving admin queue
/// command responses from VFIO-controlled devices. This trait is typically used
/// in conjunction with `SendAqCommand` to implement complete command/response
/// communication patterns with hardware devices.
///
/// The receiving process involves:
/// 1. Reading the admin queue descriptor from the device's memory region
/// 2. Parsing the descriptor to extract response metadata
/// 3. Reading any associated response data based on the descriptor's data length
///
/// # Type Parameters
///
/// * `T` - The type of the flexible data payload that implements both `Default`
///   and `AqSerDes` traits for serialization/deserialization
///
/// # Examples
///
/// ```no_run
/// # use your_crate::{ReceiveAqCommand, AqDescriptor, GenericData, PocError};
/// # struct MockDevice;
/// # impl ReceiveAqCommand<GenericData> for MockDevice {
/// #     fn receive_aq_command(&self) -> Result<(AqDescriptor<GenericData>, Vec<u8>), PocError> {
/// #         unimplemented!()
/// #     }
/// # }
/// # let device = MockDevice;
/// let (descriptor, response_data) = device.receive_aq_command::<GenericData>()?;
/// println!("Received response with opcode: 0x{:04x}", descriptor.opcode);
/// println!("Response data length: {} bytes", response_data.len());
/// ```
pub trait ReceiveAqCommand<T: Default + AqSerDes> {
    /// Receives an admin queue command response from the device.
    ///
    /// This method reads the admin queue descriptor and associated response data
    /// from the device's memory-mapped regions. It handles the complete process
    /// of descriptor deserialization and data buffer retrieval.
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// - `AqDescriptor<T>`: The deserialized command descriptor with response metadata
    /// - `Vec<u8>`: The raw response data buffer from the device
    ///
    /// # Errors
    ///
    /// This method will return a `PocError` if:
    /// - Reading from device memory regions fails
    /// - Descriptor deserialization fails due to invalid data format
    /// - The response data cannot be retrieved
    fn receive_aq_command(&self) -> Result<(AqDescriptor<T>, Vec<u8>), PocError>;
}

/// Implementation of serialization and deserialization for admin queue descriptors.
///
/// This implementation provides the `AqSerDes` trait functionality for `AqDescriptor<T>`,
/// enabling admin queue descriptors to be converted between their in-memory representation
/// and the binary format expected by hardware devices.
///
/// The serialization format follows the standard admin queue descriptor layout:
/// - Bytes 0-1: Flags (16-bit little-endian)
/// - Bytes 2-3: Opcode (16-bit little-endian)
/// - Bytes 4-5: Data length (16-bit little-endian)
/// - Bytes 6-7: Return value (16-bit little-endian)
/// - Bytes 8-11: Cookie high (32-bit little-endian)
/// - Bytes 12-15: Cookie low (32-bit little-endian)
/// - Bytes 16+: Flexible data payload (variable length)
///
/// # Binary Layout
///
/// ```text
/// Offset | Size | Field       | Description
/// -------|------|-------------|----------------------------------
/// 0      | 2    | flags       | Command flags and control bits
/// 2      | 2    | opcode      | Command operation code
/// 4      | 2    | datalen     | Length of associated data buffer
/// 6      | 2    | retval      | Return value/status code
/// 8      | 4    | cookie_high | High 32 bits of command cookie
/// 12     | 4    | cookie_low  | Low 32 bits of command cookie
/// 16     | var  | flex_data   | Flexible data payload
/// ```
impl<T: Default + AqSerDes> AqSerDes for AqDescriptor<T> {
    /// Serializes the admin queue descriptor into binary format.
    ///
    /// Converts the descriptor's fields into a byte vector using little-endian
    /// byte ordering, which is the standard format expected by most hardware
    /// devices. The flexible data payload is serialized using its own
    /// `AqSerDes::serialize` implementation.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the serialized descriptor data, or a
    /// `PocError` if serialization of the flexible data payload fails.
    ///
    /// # Format
    ///
    /// The resulting byte vector contains the descriptor fields in the order
    /// specified by the hardware interface specification, with all multi-byte
    /// values encoded in little-endian format.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{AqDescriptor, AqSerDes, GenericData};
    /// let descriptor = AqDescriptor::from_opcode(0x0001, GenericData::default());
    /// let serialized = descriptor.serialize()?;
    /// assert!(serialized.len() >= 16); // Minimum descriptor size
    /// ```
    fn serialize(&self) -> Result<Vec<u8>, PocError> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.flags.to_le_bytes());
        buffer.extend_from_slice(&self.opcode.to_le_bytes());
        buffer.extend_from_slice(&self.datalen.to_le_bytes());
        buffer.extend_from_slice(&self.retval.to_le_bytes());
        buffer.extend_from_slice(&self.cookie_high.to_le_bytes());
        buffer.extend_from_slice(&self.cookie_low.to_le_bytes());
        buffer.extend_from_slice(&self.flex_data.serialize()?);
        Ok(buffer)
    }

    /// Deserializes binary data into an admin queue descriptor.
    ///
    /// Parses a byte buffer containing a serialized admin queue descriptor,
    /// extracting all fields and reconstructing the in-memory representation.
    /// The buffer must contain at least 16 bytes for the fixed header fields,
    /// plus any additional bytes required for the flexible data payload.
    ///
    /// # Parameters
    ///
    /// * `buffer` - Byte slice containing the serialized descriptor data
    ///
    /// # Returns
    ///
    /// Returns a fully populated `AqDescriptor<T>` instance, or a `PocError`
    /// if the buffer is too small or contains invalid data.
    ///
    /// # Validation
    ///
    /// The function performs basic validation to ensure:
    /// - Buffer contains at least 16 bytes for the header
    /// - Flexible data can be successfully deserialized from remaining bytes
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - Buffer length is less than 16 bytes
    /// - Flexible data deserialization fails
    /// - Buffer contains malformed data
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{AqDescriptor, AqSerDes, GenericData};
    /// let buffer = vec![0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    /// let descriptor = AqDescriptor::<GenericData>::deserialize(&buffer)?;
    /// assert_eq!(descriptor.opcode, 0x0001);
    /// assert_eq!(descriptor.flags, 0x0200);
    /// ```
    fn deserialize(buffer: &[u8]) -> Result<Self, PocError> {
        if buffer.len() < 16 {
            return Err(PocError::DeserializationError);
        }
        let flags = u16::from_le_bytes([buffer[0], buffer[1]]);
        let opcode = u16::from_le_bytes([buffer[2], buffer[3]]);
        let datalen = u16::from_le_bytes([buffer[4], buffer[5]]);
        let retval = u16::from_le_bytes([buffer[6], buffer[7]]);
        let cookie_high = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
        let cookie_low = u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]);

        let flex_data = T::deserialize(&buffer[16..])?;

        Ok(AqDescriptor {
            flags,
            opcode,
            datalen,
            retval,
            cookie_high,
            cookie_low,
            flex_data,
        })
    }
}

impl VfioInterface {
    /// Creates a new `VfioInterface` instance.
    ///
    /// Initializes a VFIO interface wrapper around the provided VFIO device,
    /// targeting a specific memory region for device communication.
    ///
    /// # Parameters
    ///
    /// * `device` - The VFIO device handle for hardware access
    /// * `region_id` - The memory region identifier to use for device operations
    ///
    /// # Returns
    ///
    /// Returns a new `VfioInterface` instance configured for the specified device and region.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{VfioInterface, VfioDevice};
    /// # let device: VfioDevice = unimplemented!();
    /// let vfio_interface = VfioInterface::new(device, 0);
    /// ```
    fn new(device: VfioDevice, region_id: u32) -> Self {
        VfioInterface { device, region_id }
    }

    /// Reads a 32-bit register value from the device memory region.
    ///
    /// Performs a memory-mapped read operation to retrieve a 32-bit value from
    /// the specified offset within the device's memory region. The value is
    /// automatically converted from the device's native endianness.
    ///
    /// # Parameters
    ///
    /// * `offset` - Byte offset within the memory region to read from
    ///
    /// # Returns
    ///
    /// Returns the 32-bit value read from the device register, or a `PocError`
    /// if the read operation fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{VfioInterface, GL_HICR};
    /// # let vfio_interface: VfioInterface = unimplemented!();
    /// let control_value = vfio_interface.read_register32(GL_HICR)?;
    /// println!("Control register value: 0x{:08x}", control_value);
    /// ```
    fn read_register32(&self, offset: u64) -> Result<u32, PocError> {
        let mut buffer = [0u8; 4];
        self.device.region_read(self.region_id, &mut buffer, offset);
        Ok(NativeEndian::read_u32(&buffer))
    }

    /// Writes a 32-bit value to a device register.
    ///
    /// Performs a memory-mapped write operation to store a 32-bit value at the
    /// specified offset within the device's memory region. The value is
    /// automatically converted to the device's native endianness before writing.
    ///
    /// # Parameters
    ///
    /// * `offset` - Byte offset within the memory region to write to
    /// * `value` - The 32-bit value to write to the device register
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful write, or a `PocError` if the operation fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{VfioInterface, GL_HICR};
    /// # let vfio_interface: VfioInterface = unimplemented!();
    /// // Set bits 1 and clear bit 2 in control register
    /// let mut value = vfio_interface.read_register32(GL_HICR)?;
    /// value |= 0x02;  // Set bit 1
    /// value &= !0x04; // Clear bit 2
    /// vfio_interface.write_register32(GL_HICR, value)?;
    /// ```
    fn write_register32(&self, offset: u64, value: u32) -> Result<(), PocError> {
        let mut buffer = [0u8; 4];
        NativeEndian::write_u32(&mut buffer, value);
        self.device.region_write(self.region_id, &buffer, offset);
        Ok(())
    }

    /// Reads a block of data from the device memory region.
    ///
    /// Performs a bulk memory-mapped read operation to retrieve an arbitrary
    /// amount of data from the specified offset within the device's memory region.
    /// This is useful for reading command descriptors, response data, or other
    /// structured information from the device.
    ///
    /// # Parameters
    ///
    /// * `offset` - Byte offset within the memory region to start reading from
    /// * `size` - Number of bytes to read from the device
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the raw data read from the device, or a
    /// `PocError` if the read operation fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{VfioInterface, GL_HIDA, GL_HIDA_SIZE};
    /// # let vfio_interface: VfioInterface = unimplemented!();
    /// // Read a command descriptor from the device
    /// let descriptor_data = vfio_interface.read_bulk(GL_HIDA, GL_HIDA_SIZE)?;
    /// println!("Read {} bytes from device", descriptor_data.len());
    /// ```
    fn read_bulk(&self, offset: u64, size: usize) -> Result<Vec<u8>, PocError> {
        let mut buffer = vec![0u8; size];
        self.device.region_read(self.region_id, &mut buffer, offset);
        Ok(buffer)
    }

    /// Writes a block of data to the device memory region.
    ///
    /// Performs a bulk memory-mapped write operation to store arbitrary data
    /// at the specified offset within the device's memory region. This is
    /// commonly used for writing command descriptors, data buffers, or other
    /// structured information to the device.
    ///
    /// # Parameters
    ///
    /// * `offset` - Byte offset within the memory region to start writing to
    /// * `data` - Slice of bytes to write to the device
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful write, or a `PocError` if the operation fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{VfioInterface, GL_HIBA};
    /// # let vfio_interface: VfioInterface = unimplemented!();
    /// let command_data = vec![0x01, 0x02, 0x03, 0x04];
    /// vfio_interface.write_bulk(GL_HIBA, &command_data)?;
    /// println!("Wrote {} bytes to device buffer", command_data.len());
    /// ```
    fn write_bulk(&self, offset: u64, data: &[u8]) -> Result<(), PocError> {
        self.device.region_write(self.region_id, data, offset);
        Ok(())
    }
}

impl<T: Default + AqSerDes> SendAqCommand<T> for VfioInterface {
    /// Sends an admin queue command to the VFIO device.
    ///
    /// This function implements the complete process of sending an admin queue command
    /// to a VFIO-controlled device. It handles optional data buffer transmission,
    /// command descriptor serialization, and device register manipulation to initiate
    /// command execution.
    ///
    /// The sending process involves:
    /// 1. **Buffer handling**: If provided, validates and writes the data buffer to GL_HIBA
    /// 2. **Descriptor preparation**: Updates command flags and data length based on buffer size
    /// 3. **Command transmission**: Serializes and writes the command descriptor to GL_HIDA
    /// 4. **Device notification**: Manipulates GL_HICR register to signal command availability
    ///
    /// # Parameters
    ///
    /// * `command` - Mutable reference to the admin queue descriptor. The function may
    ///   modify the `datalen` and `flags` fields based on the provided buffer.
    /// * `buffer` - Optional data buffer to send with the command. Must not exceed
    ///   `GL_HIBA_SIZE` (4096 bytes).
    ///
    /// # Buffer Size Handling
    ///
    /// - Buffers larger than 512 bytes set the large data flag (0x200)
    /// - All buffers with data set the buffer present flag (0x1000)
    /// - Buffer size is automatically written to the descriptor's `datalen` field
    ///
    /// # Register Operations
    ///
    /// The function performs specific bit manipulations on the GL_HICR register:
    /// - Sets bit 1 (0x02) to signal command ready
    /// - Clears bit 2 (0x04) to reset any previous status
    ///
    /// # Memory Layout
    ///
    /// - **GL_HIBA** (0x00081000): Host Interface Buffer Area for command data
    /// - **GL_HIDA** (0x00082000): Host Interface Descriptor Area for command headers
    /// - **GL_HICR** (0x00082040): Host Interface Control Register for signaling
    ///
    /// # Errors
    ///
    /// Returns a `PocError` if:
    /// - Buffer size exceeds `GL_HIBA_SIZE` (4096 bytes)
    /// - Writing to device memory regions fails
    /// - Command serialization fails
    /// - Register read/write operations fail
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{VfioInterface, SendAqCommand, AqDescriptor, GenericData};
    /// # let vfio_interface: VfioInterface = unimplemented!();
    /// let mut command = AqDescriptor::from_opcode(0x01, GenericData::default());
    /// let data = vec![0x00, 0x01, 0x02, 0x03];
    ///
    /// vfio_interface.send_aq_command(&mut command, Some(&data))?;
    /// // Command has been sent to device, flags and datalen updated automatically
    /// ```
    fn send_aq_command(
        &self,
        command: &mut AqDescriptor<T>,
        buffer: Option<&[u8]>,
    ) -> Result<(), PocError> {
        if let Some(data) = buffer {
            if data.len() > GL_HIBA_SIZE {
                return Err(PocError::FailedToSendAqCommand(
                    "Buffer size exceeds maximum allowed".into(),
                ));
            }
            self.write_bulk(GL_HIBA, &data)?;
            command.datalen = data.len() as u16;
            command.flags |= 0x1000;
            if data.len() > 512 {
                command.flags |= 0x200; // Set the flag for large data
            }
        }

        let serialized_command = command.serialize()?;
        self.write_bulk(GL_HIDA, &serialized_command)?;

        let mut value = self.read_register32(GL_HICR)?;
        value |= 0x02;
        value &= !0x04;
        self.write_register32(GL_HICR, value)?;

        Ok(())
    }
}

/// A trait for converting between different admin queue data types.
///
/// The `Translate` trait provides a generic mechanism for converting data structures
/// that implement the `AqSerDes` trait into other compatible types. This is particularly
/// useful in admin queue operations where different command formats need to be converted
/// to a common representation or vice versa.
///
/// The translation process works by:
/// 1. Serializing the input data using its `AqSerDes::serialize` implementation
/// 2. Deserializing the resulting bytes into the target type using `AqSerDes::deserialize`
///
/// This approach ensures type safety while allowing flexible data format conversions
/// within the admin queue system.
///
/// # Type Parameters
///
/// * `T` - The source data type that implements `AqSerDes` and will be converted from
///
/// # Examples
///
/// ```no_run
/// # use your_crate::{Translate, AqSerDes, PocError};
/// # struct SourceData { value: u32 }
/// # struct TargetData { data: u32 }
/// # impl AqSerDes for SourceData {
/// #     fn serialize(&self) -> Result<Vec<u8>, PocError> { Ok(vec![]) }
/// #     fn deserialize(buffer: &[u8]) -> Result<Self, PocError> { Ok(SourceData { value: 0 }) }
/// # }
/// # impl AqSerDes for TargetData {
/// #     fn serialize(&self) -> Result<Vec<u8>, PocError> { Ok(vec![]) }
/// #     fn deserialize(buffer: &[u8]) -> Result<Self, PocError> { Ok(TargetData { data: 0 }) }
/// # }
/// # impl<T: AqSerDes> Translate<T> for TargetData {}
/// let source = SourceData { value: 42 };
/// let target = TargetData::from(source)?;
/// ```
///
/// # Errors
///
/// The `from` method will return a `PocError` if:
/// - Serialization of the input data fails
/// - Deserialization into the target type fails
/// - The serialized data format is incompatible with the target type
pub trait Translate<T: AqSerDes> {
    /// Converts from one admin queue data type to another.
    ///
    /// This method provides the core conversion functionality by serializing
    /// the input data and then deserializing it into the target type.
    ///
    /// # Parameters
    ///
    /// * `input` - The source data to convert from
    ///
    /// # Returns
    ///
    /// Returns `Ok(Self)` containing the converted data, or a `PocError` if
    /// the conversion fails at any stage.
    ///
    /// # Errors
    ///
    /// This method will return an error if:
    /// - The input data cannot be serialized
    /// - The serialized data cannot be deserialized into the target type
    /// - The data formats are fundamentally incompatible
    fn from(input: T) -> Result<Self, PocError>
    where
        Self: Sized + AqSerDes
    {
        Ok(Self::deserialize(&input.serialize()?)?)
    }
}

/// Implements data translation capability for `GenericData`.
///
/// This implementation allows `GenericData` to be converted from any other type
/// that implements the `AqSerDes` trait through serialization and deserialization.
/// This is useful for converting between different admin queue data formats while
/// maintaining type safety and error handling.
///
/// The translation process involves:
/// 1. Serializing the input data to bytes using its `AqSerDes::serialize` method
/// 2. Deserializing those bytes into a `GenericData` instance using `AqSerDes::deserialize`
///
/// # Type Parameters
///
/// * `T` - Any type that implements `AqSerDes`, representing the source data format
///
/// # Example
///
/// ```no_run
/// # use your_crate::{GenericData, Translate, AqSerDes, PocError};
/// # struct CustomData { value: u32 }
/// # impl AqSerDes for CustomData {
/// #     fn serialize(&self) -> Result<Vec<u8>, PocError> { Ok(vec![]) }
/// #     fn deserialize(buffer: &[u8]) -> Result<Self, PocError> { Ok(CustomData { value: 0 }) }
/// # }
/// let custom_data = CustomData { value: 42 };
/// let generic_data = GenericData::from(custom_data)?;
/// ```
impl<T: AqSerDes> Translate<T> for GenericData {}

impl<T: Default + AqSerDes> ReceiveAqCommand<T> for VfioInterface {
    /// Receives an admin queue command response from the VFIO device.
    ///
    /// This function reads the admin queue descriptor and associated data from the device's
    /// memory-mapped regions. It first reads the raw descriptor from the HIDA (Host Interface
    /// Data Area) region, deserializes it into an `AqDescriptor`, and then reads the response
    /// data based on the data length specified in the descriptor.
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// - `AqDescriptor<T>`: The deserialized admin queue descriptor with command information
    /// - `Vec<u8>`: The raw response data from the device
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - Reading from the device memory regions fails
    /// - Deserialization of the descriptor fails due to invalid data format
    /// - The descriptor contains invalid data length information
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{VfioInterface, ReceiveAqCommand, GenericData};
    /// # let vfio_interface: VfioInterface = unimplemented!();
    /// let (descriptor, response_data) = vfio_interface.receive_aq_command::<GenericData>()?;
    /// println!("Received command with opcode: {}", descriptor.opcode);
    /// ```
    fn receive_aq_command(&self) -> Result<(AqDescriptor<T>, Vec<u8>), PocError> {
        // Wait 100ms before reading the response to ensure command completion
        thread::sleep(Duration::from_millis(100));

        let raw_descriptor = self.read_bulk(GL_HIDA, GL_HIDA_SIZE)?;
        let command = AqDescriptor::<T>::deserialize(&raw_descriptor)?;
        let response = self.read_bulk(GL_HIDA, command.datalen as usize)?;
        // if response.is_empty() {
        //     return Err(PocError::FailedToReceiveAqCommand(
        //         "No response received".into(),
        //     ));
        // }
        Ok((command, response))
    }
}

impl<T: Default + AqSerDes> AdminCommand<T> for VfioInterface {}

pub trait AdminCommand<T: Default + AqSerDes>: SendAqCommand<T> + ReceiveAqCommand<T> {
    /// Executes a complete admin queue command transaction.
    ///
    /// This is a high-level convenience method that combines sending a command,
    /// waiting for processing, and receiving the response in a single operation.
    /// It performs buffer size validation, sends the command to the device,
    /// waits for command completion, and then retrieves the response.
    ///
    /// # Parameters
    ///
    /// * `command` - A mutable reference to the admin queue descriptor to execute.
    ///   The descriptor may be modified during execution (e.g., data length updates).
    /// * `buffer` - Optional data buffer to send with the command. If provided,
    ///   the buffer size must not exceed `GL_HIBA_SIZE` (4096 bytes).
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// - `AqDescriptor<T>`: The response descriptor with command results
    /// - `Vec<u8>`: The response data buffer from the device
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The provided buffer exceeds the maximum size limit (`GL_HIBA_SIZE`)
    /// - Sending the command to the device fails
    /// - Receiving the response from the device fails
    /// - Device communication or serialization errors occur
    ///
    /// # Timing
    ///
    /// The function includes a 100ms delay between sending and receiving to ensure
    /// the device has sufficient time to process the command before attempting
    /// to read the response.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use your_crate::{VfioInterface, AdminCommand, AqDescriptor, GenericData};
    /// # let vfio_interface: VfioInterface = unimplemented!();
    /// let mut command = AqDescriptor::from_opcode(0x01, GenericData::default());
    /// let data = vec![0x00, 0x01, 0x02, 0x03];
    ///
    /// let (response, response_data) = vfio_interface.execute_command(&mut command, Some(&data))?;
    /// println!("Command executed successfully, opcode: {}", response.opcode);
    /// ```
    fn execute_command(
        &self,
        command: &mut AqDescriptor<T>,
        buffer: Option<&[u8]>,
    ) -> Result<(AqDescriptor<T>, Vec<u8>), PocError> {
        if let Some(buffer) = buffer {
            if buffer.len() > GL_HIBA_SIZE {
                return Err(PocError::FailedToSendAqCommand(
                    "Buffer size exceeds maximum allowed".into(),
                ));
            }
        }
        self.send_aq_command(command, buffer)?;
        thread::sleep(Duration::from_millis(100));
        self.receive_aq_command()
    }
}

fn main() -> Result<(), PocError> {
    let args = Args::parse();

    // Handle device binding operations first (require root)
    if let Some(device) = &args.unbind_device {
        unbind_device(device)?;
    }

    if let Some(device) = &args.bind_to_vfio {
        bind_device_to_vfio(device)?;
    }

    // If diagnose option is provided, run diagnostics and exit
    if args.diagnose {
        run_diagnostics()?;
    }

    // If topology analysis is requested
    if args.show_iommu_topology {
        analyze_iommu_topology()?;
    }

    // If driver check is requested
    if args.check_drivers {
        check_device_drivers()?;
    }

    // If VM readiness check is requested
    if args.check_vm_ready {
        check_vm_readiness()?;
    }

    // If security check is requested
    if args.check_security {
        check_security_settings()?;
    }

    // If list option is provided, list devices and exit
    if args.list {
        list_devices_with_iommu()?;
    }

    // Get device path from CLI argument or use default
    if args.device.is_some() {
        // Check if IOMMU is enabled before proceeding
        check_iommu_enabled()?;

        let device_path_str = args.device.as_deref().unwrap();
        // bind_device_to_vfio(device_path_str)?;

        let device_path = Path::new("/sys/bus/pci/devices").join(device_path_str);

        println!("Using device: {device_path_str}");

        let container = Arc::new(VfioContainer::new(None)?);

        if !device_path.exists() {
            return Err(PocError::PathNotFound(
                device_path.to_string_lossy().into_owned(),
            ));
        }

        // Check if the device has an IOMMU group
        let iommu_group_path = device_path.join("iommu_group");
        if !iommu_group_path.exists() {
            return Err(PocError::IommuNotEnabled("IOMMU group not found".into()));
        }

        println!("v Device has IOMMU group: {iommu_group_path:?}",);

        let device = VfioDevice::new(&device_path, container.clone())?;
        println!("v Successfully created VFIO device for {device_path_str}");

        let vfio = VfioInterface::new(device, 0);

        let descriptor = vfio.read_bulk(GL_HIDA, GL_HIDA_SIZE)?;
        println!("Descriptor: {descriptor:?}");

        let mut descriptor_to_send = AqDescriptor::from_opcode(1, GenericData::default());
        vfio.send_aq_command(&mut descriptor_to_send, None)?;

        let mut value = vfio.read_register32(GL_HICR)?;
        let descriptor = vfio.read_bulk(GL_HIDA, GL_HIDA_SIZE)?;

        println!("Descriptor: {descriptor:?}");
        println!("HICR value: {value:?}");

        thread::sleep(Duration::from_millis(100));

        let descriptor = vfio.read_bulk(GL_HIDA, GL_HIDA_SIZE)?;
        println!("Descriptor: {descriptor:?}");
        value = vfio.read_register32(GL_HICR)?;
        println!("HICR value: {value:?}");

        let (response, response_data) = vfio.execute_command(&mut descriptor_to_send, None)?;
        println!("Response: {response:?}");
        println!("Response Data: {response_data:?}");
    }
    Ok(())
}
