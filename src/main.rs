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

#[derive(Error, Debug)]
pub enum PocError {
    #[error("Failed on VFIO create {0}")]
    VfioFailed(#[from] vfio_ioctls::VfioError),

    #[error("Path does not exist: {0}")]
    PathNotFound(String),

    #[error("IOMMU is not enabled on this system: {0}")]
    IommuNotEnabled(String),

    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Device binding error: {0}")]
    DeviceBindingError(String),

    #[error("Failed to send AQ command: {0}")]
    FailedToSendAqCommand(String),

    #[error("Failed to receive AQ command: {0}")]
    FailedToReceiveAqCommand(String),

    #[error("Failed to deserialize AQ command.")]
    DeserializationError,
}

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

pub struct VfioInterface {
    device: VfioDevice,
    region_id: u32,
}

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

impl<T: Default + AqSerDes> AqDescriptor<T> {
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

#[derive(Default)]
struct GenericData {
    param0: u32,
    param1: u32,
    addr_high: u32,
    addr_low: u32,
}

impl AqSerDes for GenericData {
    fn serialize(&self) -> Result<Vec<u8>, PocError> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.param0.to_le_bytes());
        buffer.extend_from_slice(&self.param1.to_le_bytes());
        buffer.extend_from_slice(&self.addr_high.to_le_bytes());
        buffer.extend_from_slice(&self.addr_low.to_le_bytes());
        Ok(buffer)
    }

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

pub trait AqSerDes {
    fn serialize(&self) -> Result<Vec<u8>, PocError>;
    fn deserialize(buffer: &[u8]) -> Result<Self, PocError>
    where
        Self: Sized;
}

pub trait SendAqCommand<T: Default + AqSerDes> {
    fn send_aq_command(
        &self,
        command: &AqDescriptor<T>,
        buffer: Option<&[u8]>,
    ) -> Result<(), PocError>;
}

pub trait ReceiveAqCommand<T: Default + AqSerDes> {
    fn receive_aq_command(&self, command: &AqDescriptor<T>) -> Result<Vec<u8>, PocError>;
}

impl<T: Default + AqSerDes> AqSerDes for AqDescriptor<T> {
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
    fn new(device: VfioDevice, region_id: u32) -> Self {
        VfioInterface { device, region_id }
    }

    fn read_register32(&self, offset: u64) -> Result<u32, PocError> {
        let mut buffer = [0u8; 4];
        self.device.region_read(self.region_id, &mut buffer, offset);
        Ok(NativeEndian::read_u32(&buffer))
    }

    fn write_register32(&self, offset: u64, value: u32) -> Result<(), PocError> {
        let mut buffer = [0u8; 4];
        NativeEndian::write_u32(&mut buffer, value);
        self.device.region_write(self.region_id, &buffer, offset);
        Ok(())
    }

    fn read_bulk(&self, offset: u64, size: usize) -> Result<Vec<u8>, PocError> {
        let mut buffer = vec![0u8; size];
        self.device.region_read(self.region_id, &mut buffer, offset);
        Ok(buffer)
    }

    fn write_bulk(&self, offset: u64, data: &[u8]) -> Result<(), PocError> {
        self.device.region_write(self.region_id, data, offset);
        Ok(())
    }
}

impl<T: Default + AqSerDes> SendAqCommand<T> for VfioInterface {
    fn send_aq_command(
        &self,
        command: &AqDescriptor<T>,
        buffer: Option<&[u8]>,
    ) -> Result<(), PocError> {
        let serialized_command = command.serialize()?;
        self.write_bulk(GL_HIDA, &serialized_command)?;
        if let Some(data) = buffer {
            self.write_bulk(GL_HIBA + serialized_command.len() as u64, data)?;
        }

        let mut value = self.read_register32(GL_HICR)?;
        value |= 0x02;
        value &= !0x04;
        self.write_register32(GL_HICR, value)?;

        Ok(())
    }
}

impl<T: Default + AqSerDes> ReceiveAqCommand<T> for VfioInterface {
    fn receive_aq_command(&self, command: &AqDescriptor<T>) -> Result<Vec<u8>, PocError> {
        let serialized_command = command.serialize()?;
        let response = self.read_bulk(GL_HIDA, serialized_command.len())?;
        if response.is_empty() {
            return Err(PocError::FailedToReceiveAqCommand(
                "No response received".into(),
            ));
        }
        Ok(response)
    }
}

impl<T: Default + AqSerDes> AdminCommand<T> for VfioInterface {}

pub trait AdminCommand<T: Default + AqSerDes>: SendAqCommand<T> + ReceiveAqCommand<T> {
    fn execute_command(
        &self,
        command: &AqDescriptor<T>,
        buffer: Option<&[u8]>,
    ) -> Result<(), PocError> {
        if let Some(buffer) = buffer {
            if buffer.len() > GL_HIBA_SIZE {
                return Err(PocError::FailedToSendAqCommand(
                    "Buffer size exceeds maximum allowed".into(),
                ));
            }
        }
        self.send_aq_command(command, buffer)?;
        thread::sleep(Duration::from_millis(100));
        self.receive_aq_command(command)?;
        Ok(())
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

        let descriptor_to_send = AqDescriptor::from_opcode(1, GenericData::default());
        vfio.send_aq_command(&descriptor_to_send, None)?;

        let mut value = vfio.read_register32(GL_HICR)?;
        let descriptor = vfio.read_bulk(GL_HIDA, GL_HIDA_SIZE)?;

        println!("Descriptor: {descriptor:?}");
        println!("HICR value: {value:?}");

        thread::sleep(Duration::from_millis(100));

        let descriptor = vfio.read_bulk(GL_HIDA, GL_HIDA_SIZE)?;
        println!("Descriptor: {descriptor:?}");
        value = vfio.read_register32(GL_HICR)?;
        println!("HICR value: {value:?}");
    }
    Ok(())
}
