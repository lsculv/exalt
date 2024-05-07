use std::{
    fs::File,
    io::{BufRead, BufReader},
};

const TOO_SMALL: [&str; 18] = [
    "char",
    "i8",
    "u8",
    "i16",
    "u16",
    "i32",
    "u32",
    "umode_t",
    "uid_t",
    "pid_t",
    "gid_t",
    "qid_t",
    "clockid_t",
    "timer_t",
    "mqd_t",
    "key_t",
    "key_serial_t",
    "rwf_t",
];

fn main() -> anyhow::Result<()> {
    let file = File::open("../include/ex/sys/syscall.h")?;
    let r = BufReader::new(file);
    'lines: for line in r
        .lines()
        .filter_map(|l| l.ok())
        .skip_while(|l| !l.starts_with("#define SYS_lsm_list_modules 461"))
        .filter(|l| !l.is_empty())
        .filter(|l| !l.starts_with('#'))
        .filter(|l| !l.starts_with('/'))
    {
        let line = line.strip_suffix("// Unimplemented").unwrap_or(&line);
        let line = line.trim();
        let signature = line.strip_suffix(';').unwrap();
        let (type_and_name, _) = line.rsplit_once('(').unwrap();
        let (return_type, name) = type_and_name.rsplit_once(' ').unwrap();
        let name = format!("SYS{}", name.strip_prefix("sys").unwrap());
        let start = line.rfind('(').unwrap();
        let end = line.rfind(')').unwrap();
        let args = &line.as_bytes()[(start + 1)..end];
        let args = std::str::from_utf8(args)?;
        let args: Vec<_> = args
            .split(",")
            .map(|a| a.rsplit_once(' ').unwrap_or(("void", "NONE")))
            .collect();
        let sysno = if *args.first().unwrap() == ("void", "NONE") {
            0
        } else {
            args.len()
        };

        let mut noreturn = false;
        let return_type = if return_type.starts_with("__attribute__((noreturn))") {
            noreturn = true;
            return_type.split_once(' ').unwrap().1
        } else {
            return_type
        };

        println!("{signature} {{");
        print!(
            "    {ret} {return_cast}syscall{sysno}({name}{comma}",
            ret = if noreturn { "" } else { "return" },
            return_cast = if TOO_SMALL.contains(&return_type.trim()) {
                format!("({return_type})(usize)")
            } else {
                format!("({return_type})")
            },
            comma = if sysno == 0 { "" } else { ", " }
        );
        for (i, &(typ, name)) in args.iter().enumerate() {
            if typ == "void" && name == "NONE" {
                println!(");");
                if noreturn {
                    println!("__builtin_unreachable();");
                }
                println!("}}");
                continue 'lines;
            }
            if TOO_SMALL.contains(&typ.trim()) {
                print!("(void*)(usize){name}");
            } else {
                print!("(void*){name}");
            }
            if i == (sysno - 1) {
                println!(");");
                if noreturn {
                    println!("    __builtin_unreachable();");
                }
                println!("}}");
            } else {
                print!(", ");
            }
        }
    }
    Ok(())
}
