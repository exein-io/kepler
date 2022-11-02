use diesel::{result, Connection};
use diesel_migrations::{MigrationConnection, RunMigrationsError};

#[derive(thiserror::Error, Debug)]
#[error("Database error.")]
pub struct MigrationError {
    #[from]
    source: RunMigrationsError,
}

pub fn setup_database<Conn>(conn: &Conn) -> Result<usize, result::Error>
where
    Conn: Connection,
{
    diesel_migrations::setup_database(conn)
}

pub fn any_pending_migrations<Conn>(conn: &Conn) -> Result<bool, MigrationError>
where
    Conn: MigrationConnection,
{
    diesel_migrations::any_pending_migrations(conn).map_err(|e| e.into())
}

pub fn run_pending_migrations<Conn>(conn: &Conn) -> Result<(), MigrationError>
where
    Conn: MigrationConnection,
{
    diesel_migrations::run_pending_migrations(conn).map_err(|e| e.into())
}
