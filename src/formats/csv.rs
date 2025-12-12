//! CSV output formatter for the Linux Memory Parser tool
use crate::error::AnalysisError;
use crate::formats::traits::OutputFormatter;
use crate::kernel::{ConnectionInfo, ModuleInfo, ProcessInfo};
use csv::Writer;

/// CSV formatter that outputs data in comma-separated values format
pub struct CsvFormatter;

impl OutputFormatter for CsvFormatter {
    fn format_processes(&self, processes: &[ProcessInfo]) -> Result<String, AnalysisError> {
        let mut wtr = Writer::from_writer(vec![]);

        // Write header
        wtr.write_record(&[
            "pid",
            "ppid",
            "comm",
            "state",
            "start_time",
            "uid",
            "gid",
            "cmdline",
        ])?;

        // Write data rows
        for proc in processes {
            wtr.write_record(&[
                proc.pid.to_string(),
                proc.ppid.to_string(),
                proc.comm.clone(),
                proc.state.clone(),
                proc.start_time.to_string(),
                proc.uid.to_string(),
                proc.gid.to_string(),
                proc.cmdline.clone(),
            ])?;
        }

        wtr.flush()?;
        let data = wtr.into_inner()?;
        Ok(String::from_utf8(data)?)
    }

    fn format_connections(&self, connections: &[ConnectionInfo]) -> Result<String, AnalysisError> {
        let mut wtr = Writer::from_writer(vec![]);

        // Write header
        wtr.write_record(&[
            "protocol",
            "local_addr",
            "local_port",
            "remote_addr",
            "remote_port",
            "state",
            "pid",
        ])?;

        // Write data rows
        for conn in connections {
            wtr.write_record(&[
                conn.protocol.clone(),
                conn.local_addr.clone(),
                conn.local_port.to_string(),
                conn.remote_addr.clone(),
                conn.remote_port.to_string(),
                conn.state.clone(),
                conn.pid.to_string(),
            ])?;
        }

        wtr.flush()?;
        let data = wtr.into_inner()?;
        Ok(String::from_utf8(data)?)
    }

    fn format_modules(&self, modules: &[ModuleInfo]) -> Result<String, AnalysisError> {
        let mut wtr = Writer::from_writer(vec![]);

        // Write header
        wtr.write_record(&["offset", "name", "size", "address"])?;

        // Write data rows
        for module in modules {
            wtr.write_record(&[
                format!("0x{:x}", module.offset),
                module.name.clone(),
                module.size.to_string(),
                format!("0x{:x}", module.address),
            ])?;
        }

        wtr.flush()?;
        let data = wtr.into_inner()?;
        Ok(String::from_utf8(data)?)
    }
}
