use std::collections::HashSet;

use cafebabe::bytecode::{Opcode, PrimitiveArrayType};
use cafebabe::constant_pool::{LiteralConstant, Loadable, MemberRef};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedByteArrayString {
    pub value: String,
    pub pc: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StackValue {
    Int(i32),
    ByteArray(usize),
    StringObject,
}

#[derive(Debug, Default)]
struct ReconstructionState {
    stack: Vec<StackValue>,
    arrays: Vec<Vec<Option<i8>>>,
}

enum StepResult {
    None,
    Reconstructed(String),
    Reset,
}

impl ReconstructionState {
    fn reset(&mut self) {
        self.stack.clear();
        self.arrays.clear();
    }

    fn pop_int(&mut self) -> Option<i32> {
        match self.stack.pop() {
            Some(StackValue::Int(value)) => Some(value),
            _ => None,
        }
    }

    fn pop_byte_array(&mut self) -> Option<usize> {
        match self.stack.pop() {
            Some(StackValue::ByteArray(array_id)) => Some(array_id),
            _ => None,
        }
    }

    fn apply_opcode(&mut self, opcode: &Opcode<'_>) -> StepResult {
        match opcode {
            Opcode::IconstM1 => {
                self.stack.push(StackValue::Int(-1));
                StepResult::None
            }
            Opcode::Iconst0 => {
                self.stack.push(StackValue::Int(0));
                StepResult::None
            }
            Opcode::Iconst1 => {
                self.stack.push(StackValue::Int(1));
                StepResult::None
            }
            Opcode::Iconst2 => {
                self.stack.push(StackValue::Int(2));
                StepResult::None
            }
            Opcode::Iconst3 => {
                self.stack.push(StackValue::Int(3));
                StepResult::None
            }
            Opcode::Iconst4 => {
                self.stack.push(StackValue::Int(4));
                StepResult::None
            }
            Opcode::Iconst5 => {
                self.stack.push(StackValue::Int(5));
                StepResult::None
            }
            Opcode::Bipush(value) => {
                self.stack.push(StackValue::Int(i32::from(*value)));
                StepResult::None
            }
            Opcode::Sipush(value) => {
                self.stack.push(StackValue::Int(i32::from(*value)));
                StepResult::None
            }
            Opcode::Ldc(loadable) | Opcode::LdcW(loadable) => match loadable {
                Loadable::LiteralConstant(LiteralConstant::Integer(value)) => {
                    self.stack.push(StackValue::Int(*value));
                    StepResult::None
                }
                _ => StepResult::Reset,
            },
            Opcode::New(class_name) if class_name.as_ref() == "java/lang/String" => {
                self.stack.push(StackValue::StringObject);
                StepResult::None
            }
            Opcode::Dup => {
                let Some(value) = self.stack.last().cloned() else {
                    return StepResult::Reset;
                };
                self.stack.push(value);
                StepResult::None
            }
            Opcode::Newarray(PrimitiveArrayType::Byte) => {
                let Some(len) = self.pop_int() else {
                    return StepResult::Reset;
                };
                if !(0..=8192).contains(&len) {
                    return StepResult::Reset;
                }

                let Ok(len) = usize::try_from(len) else {
                    return StepResult::Reset;
                };

                let array_id = self.arrays.len();
                self.arrays.push(vec![None; len]);
                self.stack.push(StackValue::ByteArray(array_id));
                StepResult::None
            }
            Opcode::Bastore => {
                let Some(value) = self.pop_int() else {
                    return StepResult::Reset;
                };
                let Some(index) = self.pop_int() else {
                    return StepResult::Reset;
                };
                let Some(array_id) = self.pop_byte_array() else {
                    return StepResult::Reset;
                };

                let Ok(index) = usize::try_from(index) else {
                    return StepResult::Reset;
                };

                let Some(array) = self.arrays.get_mut(array_id) else {
                    return StepResult::Reset;
                };

                if index >= array.len() {
                    return StepResult::Reset;
                }

                array[index] = Some(value as i8);
                StepResult::None
            }
            Opcode::Invokespecial(member) if is_string_byte_array_constructor(member) => {
                let Some(array_id) = self.pop_byte_array() else {
                    return StepResult::Reset;
                };
                let Some(StackValue::StringObject) = self.stack.pop() else {
                    return StepResult::Reset;
                };

                let Some(array) = self.arrays.get(array_id) else {
                    return StepResult::Reset;
                };

                let Some(stored_values) = array.iter().copied().collect::<Option<Vec<i8>>>() else {
                    return StepResult::Reset;
                };

                let bytes = stored_values
                    .into_iter()
                    .map(|stored| stored as u8)
                    .collect::<Vec<_>>();

                self.stack.push(StackValue::StringObject);
                StepResult::Reconstructed(String::from_utf8_lossy(&bytes).to_string())
            }
            Opcode::Nop => StepResult::None,
            _ => StepResult::Reset,
        }
    }
}

pub fn reconstruct_byte_array_strings(
    opcodes: &[(usize, Opcode<'_>)],
    exception_handler_pcs: &[u16],
) -> Vec<ReconstructedByteArrayString> {
    let handler_pcs = exception_handler_pcs
        .iter()
        .map(|pc| usize::from(*pc))
        .collect::<HashSet<_>>();
    let mut state = ReconstructionState::default();
    let mut reconstructed = Vec::new();

    for (pc, opcode) in opcodes {
        if handler_pcs.contains(pc) {
            state.reset();
        }

        if is_control_flow_boundary(opcode) {
            state.reset();
            continue;
        }

        match state.apply_opcode(opcode) {
            StepResult::None => {}
            StepResult::Reconstructed(value) => {
                reconstructed.push(ReconstructedByteArrayString {
                    value,
                    pc: u32::try_from(*pc).ok(),
                });
            }
            StepResult::Reset => state.reset(),
        }
    }

    reconstructed
}

fn is_string_byte_array_constructor(member: &MemberRef<'_>) -> bool {
    member.class_name.as_ref() == "java/lang/String"
        && member.name_and_type.name.as_ref() == "<init>"
        && member.name_and_type.descriptor.as_ref() == "([B)V"
}

fn is_control_flow_boundary(opcode: &Opcode<'_>) -> bool {
    matches!(
        opcode,
        Opcode::Goto(_)
            | Opcode::IfAcmpeq(_)
            | Opcode::IfAcmpne(_)
            | Opcode::IfIcmpeq(_)
            | Opcode::IfIcmpge(_)
            | Opcode::IfIcmpgt(_)
            | Opcode::IfIcmple(_)
            | Opcode::IfIcmplt(_)
            | Opcode::IfIcmpne(_)
            | Opcode::Ifeq(_)
            | Opcode::Ifge(_)
            | Opcode::Ifgt(_)
            | Opcode::Ifle(_)
            | Opcode::Iflt(_)
            | Opcode::Ifne(_)
            | Opcode::Ifnonnull(_)
            | Opcode::Ifnull(_)
            | Opcode::Jsr(_)
            | Opcode::Ret(_)
            | Opcode::Lookupswitch(_)
            | Opcode::Tableswitch(_)
            | Opcode::Areturn
            | Opcode::Dreturn
            | Opcode::Freturn
            | Opcode::Ireturn
            | Opcode::Lreturn
            | Opcode::Return
            | Opcode::Athrow
    )
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use cafebabe::bytecode::{Opcode, PrimitiveArrayType};
    use cafebabe::constant_pool::{MemberRef, NameAndType};

    use super::{ReconstructedByteArrayString, reconstruct_byte_array_strings};

    fn string_init_member() -> MemberRef<'static> {
        MemberRef {
            class_name: Cow::Borrowed("java/lang/String"),
            name_and_type: NameAndType {
                name: Cow::Borrowed("<init>"),
                descriptor: Cow::Borrowed("([B)V"),
            },
        }
    }

    fn hello_fixture_opcodes() -> Vec<(usize, Opcode<'static>)> {
        vec![
            (0, Opcode::New(Cow::Borrowed("java/lang/String"))),
            (3, Opcode::Dup),
            (4, Opcode::Iconst5),
            (5, Opcode::Newarray(PrimitiveArrayType::Byte)),
            (7, Opcode::Dup),
            (8, Opcode::Iconst0),
            (9, Opcode::Bipush(72)),
            (11, Opcode::Bastore),
            (12, Opcode::Dup),
            (13, Opcode::Iconst1),
            (14, Opcode::Bipush(101)),
            (16, Opcode::Bastore),
            (17, Opcode::Dup),
            (18, Opcode::Iconst2),
            (19, Opcode::Bipush(108)),
            (21, Opcode::Bastore),
            (22, Opcode::Dup),
            (23, Opcode::Iconst3),
            (24, Opcode::Bipush(108)),
            (26, Opcode::Bastore),
            (27, Opcode::Dup),
            (28, Opcode::Iconst4),
            (29, Opcode::Bipush(111)),
            (31, Opcode::Bastore),
            (32, Opcode::Invokespecial(string_init_member())),
            (35, Opcode::Areturn),
        ]
    }

    #[test]
    fn reconstructs_string_from_byte_array_pattern() {
        let reconstructed = reconstruct_byte_array_strings(&hello_fixture_opcodes(), &[]);

        assert_eq!(
            reconstructed,
            vec![ReconstructedByteArrayString {
                value: "Hello".to_string(),
                pc: Some(32),
            }]
        );
    }

    #[test]
    fn resets_state_on_unknown_opcode() {
        let mut opcodes = hello_fixture_opcodes();
        opcodes.insert(5, (6, Opcode::Aload(0)));

        let reconstructed = reconstruct_byte_array_strings(&opcodes, &[]);
        assert!(reconstructed.is_empty());
    }

    #[test]
    fn resets_state_on_exception_handler_boundary() {
        let reconstructed = reconstruct_byte_array_strings(&hello_fixture_opcodes(), &[32]);
        assert!(reconstructed.is_empty());
    }
}
