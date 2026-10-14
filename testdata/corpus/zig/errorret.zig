const E = error{Bad};

pub fn might() E!i32 {
    return E.Bad;
}
