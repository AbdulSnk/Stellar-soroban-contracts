#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol, Vec, String, Map,
};
use shared::authorization::{require_admin, require_role, Role};

#[contract]
pub struct MonitoringDashboardContract;

// Storage keys
const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const DASHBOARD_COUNTER: Symbol = symbol_short!("DASH_CNT");
const WIDGET_COUNTER: Symbol = symbol_short!("WID_CNT");

// Dashboard storage prefixes
const DASHBOARD_CONFIG: Symbol = symbol_short!("DASH_CFG");
const DASHBOARD_WIDGET: Symbol = symbol_short!("DASH_WID");
const DASHBOARD_SHARE: Symbol = symbol_short!("DASH_SHARE");
const DASHBOARD_TEMPLATE: Symbol = symbol_short!("DASH_TEMP");
const USER_PREFERENCES: Symbol = symbol_short!("USER_PREF");
const DASHBOARD_SNAPSHOT: Symbol = symbol_short!("DASH_SNAP");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ContractError {
    Unauthorized = 1,
    Paused = 2,
    InvalidInput = 3,
    NotFound = 4,
    AlreadyExists = 5,
    InvalidState = 6,
    NotInitialized = 7,
    AlreadyInitialized = 8,
    DashboardNotFound = 9,
    WidgetNotFound = 10,
    TemplateNotFound = 11,
    ShareInvalid = 12,
    SnapshotInvalid = 13,
    LayoutInvalid = 14,
}

/// Dashboard configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dashboard {
    /// Dashboard identifier
    pub dashboard_id: u64,
    /// Dashboard name
    pub name: String,
    /// Dashboard description
    pub description: String,
    /// Owner address
    pub owner: Address,
    /// Dashboard layout configuration
    pub layout: DashboardLayout,
    /// List of widgets
    pub widgets: Vec<Widget>,
    /// Time range for data display
    pub default_time_range: u64,
    /// Auto-refresh interval (seconds)
    pub auto_refresh_interval: u64,
    /// Theme configuration
    pub theme: DashboardTheme,
    /// Access permissions
    pub permissions: DashboardPermissions,
    /// Created timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub updated_at: u64,
    /// Dashboard version
    pub version: u32,
}

/// Dashboard layout configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardLayout {
    /// Layout type (grid, tabs, sections)
    pub layout_type: Symbol,
    /// Number of columns
    pub columns: u32,
    /// Number of rows
    pub rows: u32,
    /// Widget positions and sizes
    pub widget_positions: Map<u64, WidgetPosition>,
    /// Responsive breakpoints
    pub breakpoints: Map<Symbol, u32>,
}

/// Widget position and size
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WidgetPosition {
    /// Column position (0-based)
    pub column: u32,
    /// Row position (0-based)
    pub row: u32,
    /// Width in columns
    pub width: u32,
    /// Height in rows
    pub height: u32,
    /// Minimum width
    pub min_width: u32,
    /// Minimum height
    pub min_height: u32,
}

/// Dashboard widget
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Widget {
    /// Widget identifier
    pub widget_id: u64,
    /// Widget type (chart, metric, table, alert, etc.)
    pub widget_type: Symbol,
    /// Widget title
    pub title: String,
    /// Widget configuration
    pub config: Map<Symbol, String>,
    /// Data source configuration
    pub data_source: DataSource,
    /// Visualization settings
    pub visualization: VisualizationSettings,
    /// Refresh interval (seconds)
    pub refresh_interval: u64,
    /// Whether widget is visible
    pub visible: bool,
    /// Widget created timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub updated_at: u64,
}

/// Data source for widget
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataSource {
    /// Source type (contract, query, api, etc.)
    pub source_type: Symbol,
    /// Contract address (if applicable)
    pub contract_address: Option<Address>,
    /// Metric name
    pub metric_name: Option<Symbol>,
    /// Query parameters
    pub query_params: Map<Symbol, String>,
    /// Aggregation settings
    pub aggregation: Option<AggregationSettings>,
    /// Filters to apply
    pub filters: Map<Symbol, String>,
}

/// Aggregation settings for data source
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregationSettings {
    /// Aggregation function (sum, avg, min, max, count)
    pub function: Symbol,
    /// Time window for aggregation
    pub time_window: u64,
    /// Group by field
    pub group_by: Option<Symbol>,
    /// Fill missing data
    pub fill_missing: bool,
}

/// Visualization settings
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisualizationSettings {
    /// Chart type (line, bar, pie, gauge, table, etc.)
    pub chart_type: Symbol,
    /// Color scheme
    pub color_scheme: String,
    /// Axis settings
    pub axis_settings: Map<Symbol, String>,
    /// Legend settings
    pub legend_settings: Map<Symbol, String>,
    /// Animation settings
    pub animation: bool,
    /// Interactive features
    pub interactive: bool,
}

/// Dashboard theme
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardTheme {
    /// Theme name
    pub name: String,
    /// Primary color
    pub primary_color: String,
    /// Secondary color
    pub secondary_color: String,
    /// Background color
    pub background_color: String,
    /// Text color
    pub text_color: String,
    /// Font family
    pub font_family: String,
    /// Border radius
    pub border_radius: u32,
    /// Shadow settings
    pub shadow: bool,
}

/// Dashboard permissions
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardPermissions {
    /// Whether dashboard is public
    pub is_public: bool,
    /// List of allowed viewers
    pub allowed_viewers: Vec<Address>,
    /// List of allowed editors
    pub allowed_editors: Vec<Address>,
    /// Share link settings
    pub share_settings: ShareSettings,
}

/// Share settings
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareSettings {
    /// Whether sharing is enabled
    pub enabled: bool,
    /// Share token (if applicable)
    pub share_token: Option<BytesN<32>>,
    /// Share expiry timestamp
    pub expires_at: Option<u64>,
    /// Access level (view, edit)
    pub access_level: Symbol,
    /// Password protection
    pub password_protected: bool,
}

/// Dashboard template
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardTemplate {
    /// Template identifier
    pub template_id: u64,
    /// Template name
    pub name: String,
    /// Template description
    pub description: String,
    /// Template category
    pub category: Symbol,
    /// Template layout
    pub layout: DashboardLayout,
    /// Default widgets
    pub default_widgets: Vec<Widget>,
    /// Template creator
    pub creator: Address,
    /// Whether template is public
    pub is_public: bool,
    /// Usage count
    pub usage_count: u64,
    /// Rating (1-5)
    pub rating: u32,
    /// Created timestamp
    pub created_at: u64,
}

/// Dashboard snapshot
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardSnapshot {
    /// Snapshot identifier
    pub snapshot_id: u64,
    /// Dashboard ID
    pub dashboard_id: u64,
    /// Snapshot name
    pub name: String,
    /// Snapshot data (serialized dashboard state)
    pub snapshot_data: Vec<u8>,
    /// Created timestamp
    pub created_at: u64,
    /// Snapshot creator
    pub creator: Address,
    /// Whether snapshot is public
    pub is_public: bool,
}

/// User preferences
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserPreferences {
    /// User address
    pub user: Address,
    /// Default theme
    pub default_theme: String,
    /// Default time range
    pub default_time_range: u64,
    /// Preferred widgets
    pub preferred_widgets: Vec<Symbol>,
    /// Notification settings
    pub notification_settings: Map<Symbol, bool>,
    /// Language preference
    pub language: String,
    /// Timezone preference
    pub timezone: String,
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

fn get_next_dashboard_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&DASHBOARD_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&DASHBOARD_COUNTER, &(current + 1));
    current + 1
}

fn get_next_widget_id(env: &Env) -> u64 {
    let current: u64 = env.storage().persistent().get(&WIDGET_COUNTER).unwrap_or(0);
    env.storage().persistent().set(&WIDGET_COUNTER, &(current + 1));
    current + 1
}

/// Generate share token
fn generate_share_token(env: &Env, dashboard_id: u64, user: &Address) -> BytesN<32> {
    let timestamp = env.ledger().timestamp();
    let combined = format!("{}:{}:{}", dashboard_id, user, timestamp);
    // In production, use proper cryptographic hash
    BytesN::from_array(env, &[
        (dashboard_id >> 24) as u8,
        (dashboard_id >> 16) as u8,
        (dashboard_id >> 8) as u8,
        dashboard_id as u8,
        (timestamp >> 24) as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ])
}

#[contractimpl]
impl MonitoringDashboardContract {
    /// Initialize the monitoring dashboard contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&DASHBOARD_COUNTER, &0u64);
        env.storage().persistent().set(&WIDGET_COUNTER, &0u64);

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Create a new dashboard
    pub fn create_dashboard(
        env: Env,
        owner: Address,
        name: String,
        description: String,
        layout_type: Symbol,
        columns: u32,
        rows: u32,
    ) -> Result<u64, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let dashboard_id = get_next_dashboard_id(&env);

        let layout = DashboardLayout {
            layout_type,
            columns,
            rows,
            widget_positions: Map::new(&env),
            breakpoints: Map::new(&env),
        };

        let theme = DashboardTheme {
            name: String::from_str(&env, "default"),
            primary_color: String::from_str(&env, "#007bff"),
            secondary_color: String::from_str(&env, "#6c757d"),
            background_color: String::from_str(&env, "#ffffff"),
            text_color: String::from_str(&env, "#000000"),
            font_family: String::from_str(&env, "Arial"),
            border_radius: 4,
            shadow: true,
        };

        let permissions = DashboardPermissions {
            is_public: false,
            allowed_viewers: Vec::new(&env),
            allowed_editors: Vec::new(&env),
            share_settings: ShareSettings {
                enabled: false,
                share_token: None,
                expires_at: None,
                access_level: Symbol::new(&env, "view"),
                password_protected: false,
            },
        };

        let dashboard = Dashboard {
            dashboard_id,
            name: name.clone(),
            description,
            owner: owner.clone(),
            layout,
            widgets: Vec::new(&env),
            default_time_range: 86400, // 24 hours
            auto_refresh_interval: 300, // 5 minutes
            theme,
            permissions,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
            version: 1,
        };

        env.storage()
            .persistent()
            .set(&(DASHBOARD_CONFIG, dashboard_id), &dashboard);

        env.events().publish(
            (symbol_short!("dashboard_created"), owner),
            (dashboard_id, name),
        );

        Ok(dashboard_id)
    }

    /// Add widget to dashboard
    pub fn add_widget(
        env: Env,
        owner: Address,
        dashboard_id: u64,
        widget_type: Symbol,
        title: String,
        config: Map<Symbol, String>,
        data_source: DataSource,
        visualization: VisualizationSettings,
        refresh_interval: u64,
    ) -> Result<u64, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Verify dashboard ownership
        let mut dashboard: Dashboard = env
            .storage()
            .persistent()
            .get(&(DASHBOARD_CONFIG, dashboard_id))
            .ok_or(ContractError::DashboardNotFound)?;

        if dashboard.owner != owner {
            return Err(ContractError::Unauthorized);
        }

        let widget_id = get_next_widget_id(&env);

        let widget = Widget {
            widget_id,
            widget_type,
            title,
            config,
            data_source,
            visualization,
            refresh_interval,
            visible: true,
            created_at: env.ledger().timestamp(),
            updated_at: env.ledger().timestamp(),
        };

        dashboard.widgets.push_back(widget.clone());
        dashboard.updated_at = env.ledger().timestamp();
        dashboard.version += 1;

        // Update dashboard
        env.storage()
            .persistent()
            .set(&(DASHBOARD_CONFIG, dashboard_id), &dashboard);

        // Store widget separately for easier access
        env.storage()
            .persistent()
            .set(&(DASHBOARD_WIDGET, widget_id), &widget);

        env.events().publish(
            (symbol_short!("widget_added"), owner),
            (dashboard_id, widget_id),
        );

        Ok(widget_id)
    }

    /// Update widget position
    pub fn update_widget_position(
        env: Env,
        owner: Address,
        dashboard_id: u64,
        widget_id: u64,
        position: WidgetPosition,
    ) -> Result<(), ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Verify dashboard ownership
        let mut dashboard: Dashboard = env
            .storage()
            .persistent()
            .get(&(DASHBOARD_CONFIG, dashboard_id))
            .ok_or(ContractError::DashboardNotFound)?;

        if dashboard.owner != owner {
            return Err(ContractError::Unauthorized);
        }

        // Update widget position in layout
        dashboard.layout.widget_positions.set(widget_id, position);
        dashboard.updated_at = env.ledger().timestamp();
        dashboard.version += 1;

        env.storage()
            .persistent()
            .set(&(DASHBOARD_CONFIG, dashboard_id), &dashboard);

        env.events().publish(
            (symbol_short!("widget_position_updated"), owner),
            (dashboard_id, widget_id),
        );

        Ok(())
    }

    /// Share dashboard
    pub fn share_dashboard(
        env: Env,
        owner: Address,
        dashboard_id: u64,
        access_level: Symbol,
        expires_in_days: Option<u32>,
        password_protected: bool,
    ) -> Result<BytesN<32>, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Verify dashboard ownership
        let mut dashboard: Dashboard = env
            .storage()
            .persistent()
            .get(&(DASHBOARD_CONFIG, dashboard_id))
            .ok_or(ContractError::DashboardNotFound)?;

        if dashboard.owner != owner {
            return Err(ContractError::Unauthorized);
        }

        let share_token = generate_share_token(&env, dashboard_id, &owner);
        let expires_at = expires_in_days.map(|days| env.ledger().timestamp() + (days as u64 * 86400));

        dashboard.permissions.share_settings = ShareSettings {
            enabled: true,
            share_token: Some(share_token.clone()),
            expires_at,
            access_level,
            password_protected,
        };

        dashboard.updated_at = env.ledger().timestamp();
        dashboard.version += 1;

        env.storage()
            .persistent()
            .set(&(DASHBOARD_CONFIG, dashboard_id), &dashboard);

        env.events().publish(
            (symbol_short!("dashboard_shared"), owner),
            (dashboard_id, access_level),
        );

        Ok(share_token)
    }

    /// Create dashboard snapshot
    pub fn create_snapshot(
        env: Env,
        owner: Address,
        dashboard_id: u64,
        name: String,
        is_public: bool,
    ) -> Result<u64, ContractError> {
        owner.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // Verify dashboard ownership
        let dashboard: Dashboard = env
            .storage()
            .persistent()
            .get(&(DASHBOARD_CONFIG, dashboard_id))
            .ok_or(ContractError::DashboardNotFound)?;

        if dashboard.owner != owner {
            return Err(ContractError::Unauthorized);
        }

        let snapshot_id = get_next_dashboard_id(&env);

        // In production, serialize dashboard state to bytes
        let snapshot_data = Vec::new(&env);

        let snapshot = DashboardSnapshot {
            snapshot_id,
            dashboard_id,
            name,
            snapshot_data,
            created_at: env.ledger().timestamp(),
            creator: owner.clone(),
            is_public,
        };

        env.storage()
            .persistent()
            .set(&(DASHBOARD_SNAPSHOT, snapshot_id), &snapshot);

        env.events().publish(
            (symbol_short!("snapshot_created"), owner),
            (dashboard_id, snapshot_id),
        );

        Ok(snapshot_id)
    }

    /// Create dashboard template
    pub fn create_template(
        env: Env,
        creator: Address,
        name: String,
        description: String,
        category: Symbol,
        layout: DashboardLayout,
        default_widgets: Vec<Widget>,
        is_public: bool,
    ) -> Result<u64, ContractError> {
        creator.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let template_id = get_next_dashboard_id(&env);

        let template = DashboardTemplate {
            template_id,
            name,
            description,
            category,
            layout,
            default_widgets,
            creator: creator.clone(),
            is_public,
            usage_count: 0,
            rating: 0,
            created_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&(DASHBOARD_TEMPLATE, template_id), &template);

        env.events().publish(
            (symbol_short!("template_created"), creator),
            template_id,
        );

        Ok(template_id)
    }

    /// Update user preferences
    pub fn update_user_preferences(
        env: Env,
        user: Address,
        default_theme: String,
        default_time_range: u64,
        preferred_widgets: Vec<Symbol>,
        language: String,
        timezone: String,
    ) -> Result<(), ContractError> {
        user.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        let preferences = UserPreferences {
            user: user.clone(),
            default_theme,
            default_time_range,
            preferred_widgets,
            notification_settings: Map::new(&env),
            language,
            timezone,
        };

        env.storage()
            .persistent()
            .set(&(USER_PREFERENCES, user), &preferences);

        env.events().publish(
            (symbol_short!("preferences_updated"), user),
            (),
        );

        Ok(())
    }

    /// Pause/unpause contract (admin only)
    pub fn set_paused(env: Env, admin: Address, paused: bool) -> Result<(), ContractError> {
        admin.require_auth();

        let stored_admin: Address = env.storage().persistent().get(&ADMIN).ok_or(ContractError::NotInitialized)?;
        if admin != stored_admin {
            return Err(ContractError::Unauthorized);
        }

        set_paused(&env, paused);

        env.events().publish(
            (symbol_short!("paused"), admin),
            paused,
        );

        Ok(())
    }

    // ===== View Functions =====

    /// Get dashboard configuration
    pub fn get_dashboard(env: Env, dashboard_id: u64) -> Option<Dashboard> {
        env.storage().persistent().get(&(DASHBOARD_CONFIG, dashboard_id))
    }

    /// Get widget configuration
    pub fn get_widget(env: Env, widget_id: u64) -> Option<Widget> {
        env.storage().persistent().get(&(DASHBOARD_WIDGET, widget_id))
    }

    /// Get dashboard template
    pub fn get_template(env: Env, template_id: u64) -> Option<DashboardTemplate> {
        env.storage().persistent().get(&(DASHBOARD_TEMPLATE, template_id))
    }

    /// Get dashboard snapshot
    pub fn get_snapshot(env: Env, snapshot_id: u64) -> Option<DashboardSnapshot> {
        env.storage().persistent().get(&(DASHBOARD_SNAPSHOT, snapshot_id))
    }

    /// Get user preferences
    pub fn get_user_preferences(env: Env, user: Address) -> Option<UserPreferences> {
        env.storage().persistent().get(&(USER_PREFERENCES, user))
    }

    /// List dashboards for user
    pub fn list_user_dashboards(env: Env, user: Address) -> Vec<Dashboard> {
        // In production, query dashboards where user is owner or has access
        // For now, return empty vector
        Vec::new(&env)
    }

    /// List public templates
    pub fn list_public_templates(env: Env, category: Option<Symbol>) -> Vec<DashboardTemplate> {
        // In production, query public templates by category
        // For now, return empty vector
        Vec::new(&env)
    }

    /// Get dashboard statistics
    pub fn get_dashboard_stats(env: Env, dashboard_id: u64) -> (u64, u64, u64) {
        // Returns (widget_count, view_count, last_updated_timestamp)
        // In production, calculate from actual data
        (0, 0, 0)
    }

    /// Validate share token
    pub fn validate_share_token(
        env: Env,
        dashboard_id: u64,
        share_token: BytesN<32>,
    ) -> Result<bool, ContractError> {
        // In production, validate share token and check expiry
        // For now, return false
        Ok(false)
    }
}
