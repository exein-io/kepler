use std::{convert::TryFrom, fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpeType {
    Any,
    Hardware,
    OperatingSystem,
    Application,
}

impl TryFrom<&str> for CpeType {
    type Error = String;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        Self::from_str(val)
    }
}

impl FromStr for CpeType {
    type Err = String;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        if val == "ANY" {
            return Ok(Self::Any);
        }

        let c = {
            let c = val.chars().next();
            c.ok_or("No chars for type")?
        };
        match c {
            'h' => Ok(Self::Hardware),
            'o' => Ok(Self::OperatingSystem),
            'a' => Ok(Self::Application),
            _ => Err(format!("could not convert '{}' to cpe type", c)),
        }
    }
}

impl fmt::Display for CpeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Any => {
                if f.alternate() {
                    write!(f, "*")
                } else {
                    write!(f, "ANY")
                }
            }
            Self::Hardware => write!(f, "h"),
            Self::OperatingSystem => write!(f, "o"),
            Self::Application => write!(f, "a"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::CpeType;

    #[test]
    fn can_parse_strings_correctly() {
        let mut table = HashMap::new();

        table.insert("h", CpeType::Hardware);
        table.insert("o", CpeType::OperatingSystem);
        table.insert("a", CpeType::Application);

        for (s, t) in table {
            let res = s.parse::<CpeType>();
            assert_eq!(t, res.unwrap());
        }
    }

    #[test]
    fn can_detect_invalid_strings() {
        assert!("troll".parse::<CpeType>().is_err());
    }
}
