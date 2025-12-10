//! Text (table) output formatter for the Linux Memory Parser tool
use crate::formats::traits::OutputFormatter;
use crate::kernel::{ProcessInfo, ConnectionInfo, ModuleInfo};
use crate::error::AnalysisError;
use prettytable::{Table, Row, Cell};

/// Text formatter that outputs data in a human-readable table format
pub struct TextFormatter;

impl OutputFormatter for TextFormatter {
    fn format_processes(&self, processes: &[ProcessInfo]) -> Result<String, AnalysisError> {
        let mut table = Table::new();
        table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        // Header
        table.add_row(Row::new(vec![
            Cell::new("PID").style_spec("c"),
            Cell::new("PPID").style_spec("c"), 
            Cell::new("COMM").style_spec("c"),
            Cell::new("STATE").style_spec("c"),
            Cell::new("START_TIME").style_spec("c"),
            Cell::new("UID").style_spec("c"),
            Cell::new("GID").style_spec("c"),
            Cell::new("CMDLINE").style_spec("c"),
        ]));

        // Data rows
        for proc in processes {
            table.add_row(Row::new(vec![
                Cell::new(&proc.pid.to_string()),
                Cell::new(&proc.ppid.to_string()),
                Cell::new(&proc.comm),
                Cell::new(&proc.state),
                Cell::new(&proc.start_time.to_string()),
                Cell::new(&proc.uid.to_string()),
                Cell::new(&proc.gid.to_string()),
                Cell::new(&proc.cmdline),
            ]));
        }

        Ok(table.to_string())
    }

    fn format_connections(&self, connections: &[ConnectionInfo]) -> Result<String, AnalysisError> {
        let mut table = Table::new();
        table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        // Header
        table.add_row(Row::new(vec![
            Cell::new("PROTO").style_spec("c"),
            Cell::new("LOCAL_ADDR").style_spec("c"),
            Cell::new("LOCAL_PORT").style_spec("c"),
            Cell::new("REMOTE_ADDR").style_spec("c"),
            Cell::new("REMOTE_PORT").style_spec("c"),
            Cell::new("STATE").style_spec("c"),
            Cell::new("PID").style_spec("c"),
        ]));

        // Data rows
        for conn in connections {
            table.add_row(Row::new(vec![
                Cell::new(&conn.protocol),
                Cell::new(&conn.local_addr),
                Cell::new(&conn.local_port.to_string()),
                Cell::new(&conn.remote_addr),
                Cell::new(&conn.remote_port.to_string()),
                Cell::new(&conn.state),
                Cell::new(&conn.pid.to_string()),
            ]));
        }

        Ok(table.to_string())
    }

    fn format_modules(&self, modules: &[ModuleInfo]) -> Result<String, AnalysisError> {
        let mut table = Table::new();
        table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        // Header
        table.add_row(Row::new(vec![
            Cell::new("OFFSET").style_spec("c"),
            Cell::new("NAME").style_spec("c"),
            Cell::new("SIZE").style_spec("c"),
            Cell::new("ADDRESS").style_spec("c"),
        ]));

        // Data rows
        for module in modules {
            table.add_row(Row::new(vec![
                Cell::new(&format!("0x{:x}", module.offset)),
                Cell::new(&module.name),
                Cell::new(&module.size.to_string()),
                Cell::new(&format!("0x{:x}", module.address)),
            ]));
        }

        Ok(table.to_string())
    }
}