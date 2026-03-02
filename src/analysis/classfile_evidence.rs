use anyhow::{anyhow, Result};
use cafebabe::attributes::AttributeData;
use cafebabe::bytecode::Opcode;
use cafebabe::{parse_class_with_options, ParseOptions};

use crate::ArchiveEntry;

use super::{BytecodeEvidence, BytecodeEvidenceItem, Location, LocationMethod};

pub fn extract_bytecode_evidence(entries: &[ArchiveEntry]) -> BytecodeEvidence {
    let mut items = Vec::new();

    for entry in entries {
        if !entry.path.ends_with(".class") {
            continue;
        }

        if let Ok(mut class_items) = extract_entry_evidence(entry) {
            items.append(&mut class_items);
        }
    }

    BytecodeEvidence { items }
}

fn extract_entry_evidence(entry: &ArchiveEntry) -> Result<Vec<BytecodeEvidenceItem>> {
    let mut parse_options = ParseOptions::default();
    parse_options.parse_bytecode(true);

    let class = parse_class_with_options(entry.bytes.as_slice(), &parse_options)
        .map_err(|e| anyhow!("failed to parse class {}: {e}", entry.path))?;
    let class_name = class.this_class.to_string();

    let (utf8_items, string_literals) = parse_constant_pool_strings(entry.bytes.as_slice())?;

    let mut items = Vec::with_capacity(utf8_items.len() + string_literals.len());

    for value in utf8_items {
        items.push(BytecodeEvidenceItem::CpUtf8 {
            value,
            location: Location {
                entry_path: entry.path.clone(),
                class_name: class_name.clone(),
                method: None,
                pc: None,
            },
        });
    }

    for value in string_literals {
        items.push(BytecodeEvidenceItem::CpStringLiteral {
            value,
            location: Location {
                entry_path: entry.path.clone(),
                class_name: class_name.clone(),
                method: None,
                pc: None,
            },
        });
    }

    items.extend(extract_method_invoke_evidence(
        &class,
        entry.path.as_str(),
        class_name.as_str(),
    ));

    Ok(items)
}

fn extract_method_invoke_evidence(
    class: &cafebabe::ClassFile<'_>,
    entry_path: &str,
    class_name: &str,
) -> Vec<BytecodeEvidenceItem> {
    let mut items = Vec::new();

    for method in &class.methods {
        let method_location = LocationMethod {
            name: method.name.to_string(),
            descriptor: method.descriptor.to_string(),
        };

        for attribute in &method.attributes {
            let AttributeData::Code(code_data) = &attribute.data else {
                continue;
            };

            let Some(bytecode) = &code_data.bytecode else {
                continue;
            };

            for (pc, opcode) in &bytecode.opcodes {
                let location = Location {
                    entry_path: entry_path.to_string(),
                    class_name: class_name.to_string(),
                    method: Some(method_location.clone()),
                    pc: u32::try_from(*pc).ok(),
                };

                match opcode {
                    Opcode::Invokevirtual(member)
                    | Opcode::Invokestatic(member)
                    | Opcode::Invokespecial(member)
                    | Opcode::Invokeinterface(member, _) => {
                        items.push(BytecodeEvidenceItem::InvokeResolved {
                            owner: member.class_name.to_string(),
                            name: member.name_and_type.name.to_string(),
                            descriptor: member.name_and_type.descriptor.to_string(),
                            location,
                        });
                    }
                    Opcode::Invokedynamic(dynamic) => {
                        items.push(BytecodeEvidenceItem::InvokeDynamic {
                            name: dynamic.name_and_type.name.to_string(),
                            descriptor: dynamic.name_and_type.descriptor.to_string(),
                            bootstrap_attr_index: dynamic.attr_index,
                            location,
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    items
}

fn parse_constant_pool_strings(raw: &[u8]) -> Result<(Vec<String>, Vec<String>)> {
    let mut offset = 0usize;
    let magic = read_u4(raw, &mut offset)?;
    if magic != 0xCAFE_BABE {
        return Err(anyhow!("invalid class magic"));
    }

    let _minor_version = read_u2(raw, &mut offset)?;
    let _major_version = read_u2(raw, &mut offset)?;
    let cp_count = usize::from(read_u2(raw, &mut offset)?);

    let mut utf8_by_index: Vec<Option<String>> = vec![None; cp_count];
    let mut string_index_refs: Vec<u16> = Vec::new();

    let mut cp_index = 1usize;
    while cp_index < cp_count {
        let tag = read_u1(raw, &mut offset)?;
        match tag {
            1 => {
                let len = usize::from(read_u2(raw, &mut offset)?);
                let value_bytes = take_bytes(raw, &mut offset, len)?;
                let value = cesu8::from_java_cesu8(value_bytes)
                    .map(|decoded| decoded.into_owned())
                    .unwrap_or_else(|_| {
                        value_bytes
                            .iter()
                            .map(|byte| format!("\\x{byte:02x}"))
                            .collect()
                    });
                utf8_by_index[cp_index] = Some(value);
            }
            3 | 4 => {
                take_bytes(raw, &mut offset, 4)?;
            }
            5 | 6 => {
                take_bytes(raw, &mut offset, 8)?;
                cp_index += 1;
            }
            7 | 16 | 19 | 20 => {
                take_bytes(raw, &mut offset, 2)?;
            }
            8 => {
                let utf8_index = read_u2(raw, &mut offset)?;
                string_index_refs.push(utf8_index);
            }
            9 | 10 | 11 | 12 | 17 | 18 => {
                take_bytes(raw, &mut offset, 4)?;
            }
            15 => {
                take_bytes(raw, &mut offset, 3)?;
            }
            _ => {
                return Err(anyhow!("unsupported constant pool tag {tag}"));
            }
        }

        cp_index += 1;
    }

    let cp_utf8_values = utf8_by_index
        .iter()
        .skip(1)
        .filter_map(|value| value.clone())
        .collect::<Vec<_>>();

    let mut string_literals = Vec::new();
    for utf8_index in string_index_refs {
        if let Some(Some(value)) = utf8_by_index.get(usize::from(utf8_index)) {
            string_literals.push(value.clone());
        }
    }

    Ok((cp_utf8_values, string_literals))
}

fn read_u1(raw: &[u8], offset: &mut usize) -> Result<u8> {
    let bytes = take_bytes(raw, offset, 1)?;
    Ok(bytes[0])
}

fn read_u2(raw: &[u8], offset: &mut usize) -> Result<u16> {
    let bytes = take_bytes(raw, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u4(raw: &[u8], offset: &mut usize) -> Result<u32> {
    let bytes = take_bytes(raw, offset, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn take_bytes<'a>(raw: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| anyhow!("offset overflow while parsing class file"))?;
    if end > raw.len() {
        return Err(anyhow!(
            "unexpected end of class file while parsing constant pool"
        ));
    }

    let bytes = &raw[*offset..end];
    *offset = end;
    Ok(bytes)
}
