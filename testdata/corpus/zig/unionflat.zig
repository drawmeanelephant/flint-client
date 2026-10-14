const Value = union {
    int: i32,
    float: f64,
    none: void,
};

const Opt = union {
    some: i32,
    none,
};
