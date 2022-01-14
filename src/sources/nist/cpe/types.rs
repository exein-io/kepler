use std::convert::TryFrom;

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Any,
    Hardware,
    OperatingSystem,
    Application,
}

impl Default for Type {
    fn default() -> Self {
        Self::Any
    }
}

impl TryFrom<&str> for Type {
    type Error = String;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        Self::from_str(val)
    }
}

impl Type {
    pub fn from_str(val: &str) -> Result<Self, String> {
        if val == "ANY" {
            return Ok(Self::Any);
        }
        let c = {
            let c = val.chars().next();
            c.unwrap()
        };
        match c {
            'h' => Ok(Self::Hardware),
            'o' => Ok(Self::OperatingSystem),
            'a' => Ok(Self::Application),
            _ => Err(format!("could not convert '{}' to cpe type", c)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::Type;

    #[test]
    fn can_parse_strings_correctly() {
        let mut table = HashMap::new();

        table.insert("h", Type::Hardware);
        table.insert("o", Type::OperatingSystem);
        table.insert("a", Type::Application);

        for (s, t) in table {
            let res = Type::from_str(s);
            assert_eq!(t, res.unwrap());
        }
    }

    #[test]
    fn can_detect_invalid_strings() {
        assert!(Type::from_str("troll").is_err());
    }
}
