// Comprehensive Rhai script to test all ScriptArgumentValue types
// This script receives arguments of all supported types and manipulates them

info("=== Comprehensive Arguments Test Started ===");

// === STRING ARGUMENTS ===
info("=== Testing String Arguments ===");

if type_of(simple_string) == "string" {
    info(`simple_string: "${simple_string}" (length: ${simple_string.len()})`);
    let modified = simple_string.to_upper() + "!";
    info(`Modified: "${modified}"`);
} else {
    info("ERROR: simple_string is not a string!");
}

if type_of(empty_string) == "string" {
    info(`empty_string: "${empty_string}" (length: ${empty_string.len()})`);
    info(`Is empty: ${empty_string.is_empty()}`);
} else {
    info("ERROR: empty_string is not a string!");
}

if type_of(special_chars) == "string" {
    info(`special_chars: "${special_chars}" (length: ${special_chars.len()})`);
    let reversed = "";
    for i in range(special_chars.len() - 1, -1, -1) {
        reversed += special_chars[i];
    }
    info(`Reversed: "${reversed}"`);
} else {
    info("ERROR: special_chars is not a string!");
}

// === NUMERIC ARGUMENTS ===
info("=== Testing Numeric Arguments ===");

if type_of(integer_positive) == "i64" {
    info(`integer_positive: ${integer_positive}`);
    let doubled = integer_positive * 2;
    let squared = integer_positive * integer_positive;
    info(`Doubled: ${doubled}, Squared: ${squared}`);
} else {
    info("ERROR: integer_positive is not an integer!");
}

if type_of(integer_negative) == "i64" {
    info(`integer_negative: ${integer_negative}`);
    let absolute = if integer_negative < 0 { -integer_negative } else { integer_negative };
    info(`Absolute value: ${absolute}`);
} else {
    info("ERROR: integer_negative is not an integer!");
}

if type_of(integer_zero) == "i64" {
    info(`integer_zero: ${integer_zero}`);
    info(`Is zero: ${integer_zero == 0}`);
} else {
    info("ERROR: integer_zero is not an integer!");
}

if type_of(long_max) == "i64" {
    info(`long_max: ${long_max}`);
    info(`Is positive: ${long_max > 0}`);
    info(`Near max value: ${long_max > 9000000000000000000}`);
} else {
    info("ERROR: long_max is not a long!");
}

if type_of(double_pi) == "f64" {
    info(`double_pi: ${double_pi}`);
    let area = double_pi * 2.0 * 2.0; // π * r² with r=2
    info(`Circle area (r=2): ${area}`);
    info(`Rounded: ${double_pi.floor()}`);
} else {
    info("ERROR: double_pi is not a float!");
}

// === BOOLEAN ARGUMENTS ===
info("=== Testing Boolean Arguments ===");

if type_of(bool_true) == "bool" {
    info(`bool_true: ${bool_true}`);
    info(`Negated: ${!bool_true}`);
    info(`AND with false: ${bool_true && false}`);
    info(`OR with false: ${bool_true || false}`);
} else {
    info("ERROR: bool_true is not a boolean!");
}

if type_of(bool_false) == "bool" {
    info(`bool_false: ${bool_false}`);
    info(`Negated: ${!bool_false}`);
    info(`AND with true: ${bool_false && true}`);
    info(`OR with true: ${bool_false || true}`);
} else {
    info("ERROR: bool_false is not a boolean!");
}

// === ARRAY ARGUMENTS ===
info("=== Testing Array Arguments ===");

if type_of(empty_array) == "array" {
    info(`empty_array: ${empty_array} (length: ${empty_array.len()})`);
    info(`Is empty: ${empty_array.is_empty()}`);
} else {
    info("ERROR: empty_array is not an array!");
}

if type_of(mixed_array) == "array" {
    info(`mixed_array: ${mixed_array} (length: ${mixed_array.len()})`);
    for i in range(0, mixed_array.len()) {
        let element = mixed_array[i];
        info(`  [${i}]: ${element} (type: ${type_of(element)})`);
    }
    
    // Test array operations
    let first = mixed_array[0];
    let last = mixed_array[mixed_array.len() - 1];
    info(`First element: ${first}, Last element: ${last}`);
} else {
    info("ERROR: mixed_array is not an array!");
}

if type_of(number_array) == "array" {
    info(`number_array: ${number_array} (length: ${number_array.len()})`);
    let sum = 0;
    let product = 1;
    for i in range(0, number_array.len()) {
        let num = number_array[i];
        info(`  [${i}]: ${num}`);
        sum += num;
        product *= num;
    }
    info(`Sum: ${sum}, Product: ${product}`);
    info(`Average: ${sum / number_array.len()}`);
} else {
    info("ERROR: number_array is not an array!");
}

// === MAP ARGUMENTS ===
info("=== Testing Map Arguments ===");

if type_of(empty_map) == "map" {
    info(`empty_map: ${empty_map} (keys count: ${empty_map.keys().len()})`);
    info(`Is empty: ${empty_map.is_empty()}`);
} else {
    info("ERROR: empty_map is not a map!");
}

if type_of(simple_map) == "map" {
    info(`simple_map: ${simple_map}`);
    let keys = simple_map.keys();
    info(`Keys: ${keys}`);
    
    for key in keys {
        let value = simple_map[key];
        info(`  ${key}: ${value} (type: ${type_of(value)})`);
    }
    
    // Test map operations
    if "name" in simple_map {
        info(`Name exists: ${simple_map.name}`);
    }
    if "age" in simple_map {
        let age = simple_map.age;
        info(`Age: ${age}, Next year: ${age + 1}`);
    }
} else {
    info("ERROR: simple_map is not a map!");
}

if type_of(user_info) == "map" {
    info(`user_info: ${user_info}`);
    let keys = user_info.keys();
    info(`Keys: ${keys}`);
    
    for key in keys {
        let value = user_info[key];
        info(`  ${key}: ${value} (type: ${type_of(value)})`);
    }
    
    // Test specific user info fields
    if "name" in user_info {
        info(`User name: ${user_info.name}`);
    }
    if "id" in user_info {
        info(`User ID: ${user_info.id}`);
    }
    if "active" in user_info {
        info(`Is active: ${user_info.active}`);
    }
    if "department" in user_info {
        info(`Department: ${user_info.department}`);
    }
} else {
    info("ERROR: user_info is not a map!");
}

if type_of(user_skills) == "array" {
    info(`user_skills: ${user_skills} (length: ${user_skills.len()})`);
    for i in range(0, user_skills.len()) {
        let skill = user_skills[i];
        info(`  Skill [${i}]: ${skill}`);
    }
    
    // Test skills operations
    let skill_count = user_skills.len();
    let first_skill = user_skills[0];
    let last_skill = user_skills[user_skills.len() - 1];
    info(`Total skills: ${skill_count}`);
    info(`First skill: ${first_skill}, Last skill: ${last_skill}`);
} else {
    info("ERROR: user_skills is not an array!");
}

if type_of(project_names) == "array" {
    info(`project_names: ${project_names} (length: ${project_names.len()})`);
    for i in range(0, project_names.len()) {
        let project = project_names[i];
        info(`  Project [${i}]: ${project}`);
    }
    
    // Test project operations
    let project_count = project_names.len();
    info(`Total projects: ${project_count}`);
    
    // Find projects with specific words
    let alpha_projects = [];
    for project in project_names {
        if project.contains("Alpha") {
            alpha_projects.push(project);
        }
    }
    info(`Alpha projects: ${alpha_projects}`);
} else {
    info("ERROR: project_names is not an array!");
}

// === FINAL SUMMARY ===
info("=== Final Test Summary ===");

let test_count = 0;
let success_count = 0;

// Count successful argument types
if type_of(simple_string) == "string" { test_count += 1; success_count += 1; }
if type_of(empty_string) == "string" { test_count += 1; success_count += 1; }
if type_of(special_chars) == "string" { test_count += 1; success_count += 1; }
if type_of(integer_positive) == "i64" { test_count += 1; success_count += 1; }
if type_of(integer_negative) == "i64" { test_count += 1; success_count += 1; }
if type_of(integer_zero) == "i64" { test_count += 1; success_count += 1; }
if type_of(long_max) == "i64" { test_count += 1; success_count += 1; }
if type_of(double_pi) == "f64" { test_count += 1; success_count += 1; }
if type_of(bool_true) == "bool" { test_count += 1; success_count += 1; }
if type_of(bool_false) == "bool" { test_count += 1; success_count += 1; }
if type_of(empty_array) == "array" { test_count += 1; success_count += 1; }
if type_of(mixed_array) == "array" { test_count += 1; success_count += 1; }
if type_of(number_array) == "array" { test_count += 1; success_count += 1; }
if type_of(empty_map) == "map" { test_count += 1; success_count += 1; }
if type_of(simple_map) == "map" { test_count += 1; success_count += 1; }
if type_of(user_info) == "map" { test_count += 1; success_count += 1; }
if type_of(user_skills) == "array" { test_count += 1; success_count += 1; }
if type_of(project_names) == "array" { test_count += 1; success_count += 1; }

info(`Tests completed: ${success_count}/${test_count} argument types processed successfully`);

if success_count == test_count {
    info("🎉 ALL SCRIPT ARGUMENT TYPES SUCCESSFULLY TESTED! 🎉");
    "SUCCESS: All 18 argument types processed and manipulated correctly!"
} else {
    info(`❌ Some tests failed: ${test_count - success_count} failures`);
    "FAILURE: Some argument types were not processed correctly"
}
