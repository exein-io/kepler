use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Component {
    Any,
    NotApplicable,
    Value(String),
}

impl TryFrom<&str> for Component {
    type Error = String;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        Self::from_str(val)
    }
}

impl FromStr for Component {
    type Err = String;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        Ok(match val {
            "*" => Component::Any,
            "-" => Component::NotApplicable,
            _ => Component::Value(val.to_owned()),
        })
    }
}

impl Component {
    #[allow(dead_code)]
    fn matches(&self, val: &str) -> bool {
        match self {
            Component::Any => true,
            Component::NotApplicable => false,
            Component::Value(v) => v == val,
        }
    }

    pub fn is_any(&self) -> bool {
        matches!(self, Component::Any)
    }

    pub fn is_na(&self) -> bool {
        matches!(self, Component::NotApplicable)
    }

    pub fn is_value(&self) -> bool {
        matches!(self, Component::Value(_))
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Component::Any => "*".to_owned(),
                Component::NotApplicable => "-".to_owned(),
                Component::Value(v) => v.to_owned(),
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::Component;

    #[test]
    fn can_parse_strings_correctly() {
        let mut table = HashMap::new();

        table.insert("*", Component::Any);
        table.insert("-", Component::NotApplicable);
        table.insert("**", Component::Value("**".to_owned()));
        table.insert("--", Component::Value("--".to_owned()));
        table.insert("foo", Component::Value("foo".to_owned()));

        for (s, c) in table {
            let res = s.parse::<Component>();
            assert!(res.is_ok());
            assert_eq!(c, res.unwrap());
        }
    }

    #[test]
    fn can_match_strings_correctly() {
        struct StringMatch(&'static str, bool);

        let mut table = HashMap::new();

        table.insert(Component::Any, StringMatch("literally anything", true));
        table.insert(
            Component::NotApplicable,
            StringMatch("literally nothing", false),
        );
        table.insert(Component::NotApplicable, StringMatch("", false));
        table.insert(Component::NotApplicable, StringMatch("-", false));

        table.insert(
            Component::Value("1.0.0".to_owned()),
            StringMatch("-", false),
        );
        table.insert(
            Component::Value("1.0.0".to_owned()),
            StringMatch("1.0.0", true),
        );

        for (c, m) in table {
            assert_eq!(m.1, c.matches(m.0));
        }
    }
}
