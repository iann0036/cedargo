extern crate libc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request, Response, Schema, ValidationMode, ValidationResult, Validator,
};
use std::ffi::{CStr, CString};
use std::str::FromStr;

#[no_mangle]
pub extern "C" fn CedarValidate(
    src: *const libc::c_char,
    sc: *const libc::c_char,
) -> *const libc::c_char {
    let cstr_src = unsafe { CStr::from_ptr(src) };
    let str_src = cstr_src.to_str().unwrap();
    let cstr_sc = unsafe { CStr::from_ptr(sc) };
    let str_sc = cstr_sc.to_str().unwrap();
    CString::new(validate(str_src, str_sc)).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn CedarEvaluate(
    pid: *const libc::c_char,
    ptype: *const libc::c_char,
    aid: *const libc::c_char,
    atype: *const libc::c_char,
    rid: *const libc::c_char,
    rtype: *const libc::c_char,
    pol: *const libc::c_char,
    ctx: *const libc::c_char,
    ent: *const libc::c_char,
) -> *const libc::c_char {
    let cstr_pid = unsafe { CStr::from_ptr(pid) };
    let str_pid = cstr_pid.to_str().unwrap();
    let cstr_ptype = unsafe { CStr::from_ptr(ptype) };
    let str_ptype = cstr_ptype.to_str().unwrap();
    let cstr_aid = unsafe { CStr::from_ptr(aid) };
    let str_aid = cstr_aid.to_str().unwrap();
    let cstr_atype = unsafe { CStr::from_ptr(atype) };
    let str_atype = cstr_atype.to_str().unwrap();
    let cstr_rid = unsafe { CStr::from_ptr(rid) };
    let str_rid = cstr_rid.to_str().unwrap();
    let cstr_rtype = unsafe { CStr::from_ptr(rtype) };
    let str_rtype = cstr_rtype.to_str().unwrap();
    let cstr_pol = unsafe { CStr::from_ptr(pol) };
    let str_pol = cstr_pol.to_str().unwrap();
    let cstr_ctx = unsafe { CStr::from_ptr(ctx) };
    let str_ctx = cstr_ctx.to_str().unwrap();
    let cstr_ent = unsafe { CStr::from_ptr(ent) };
    let str_ent = cstr_ent.to_str().unwrap();

    CString::new(evaluate(
        str_pid, str_ptype, str_aid, str_atype, str_rid, str_rtype, str_pol, str_ctx, str_ent,
    ))
    .unwrap()
    .into_raw()
}

fn evaluate<'a>(
    pid: &'a str,
    ptype: &'a str,
    aid: &'a str,
    atype: &'a str,
    rid: &'a str,
    rtype: &'a str,
    pol: &'a str,
    ctx: &'a str,
    ent: &'a str,
) -> &'a str {
    let c = Context::from_json_str(ctx, None).unwrap();

    let p_eid = EntityId::from_str(pid).unwrap();
    let p_name: EntityTypeName = EntityTypeName::from_str(ptype).unwrap();
    let p = EntityUid::from_type_name_and_id(p_name, p_eid);

    let a_eid = EntityId::from_str(aid).unwrap();
    let a_name: EntityTypeName = EntityTypeName::from_str(atype).unwrap();
    let a = EntityUid::from_type_name_and_id(a_name, a_eid);

    let r_eid = EntityId::from_str(rid).unwrap();
    let r_name: EntityTypeName = EntityTypeName::from_str(rtype).unwrap();
    let r = EntityUid::from_type_name_and_id(r_name, r_eid);

    // create a request
    let request: Request = Request::new(Some(p), Some(a), Some(r), c);

    // create a policy
    let ps = PolicySet::from_str(pol).expect("policy error");

    let entities = Entities::from_json_str(ent, None).expect("entity error");
    let ans = execute_query(&request, ps, entities);

    let ret = match ans.decision() {
        Decision::Allow => "ALLOW",
        Decision::Deny => "DENY",
    };

    print_response(ans);

    ret
}

/// Prints the Answer from the Authorization
fn print_response(ans: Response) {
    match ans.decision() {
        Decision::Allow => println!("ALLOW"),
        Decision::Deny => println!("DENY"),
    }

    println!();
    for err in ans.diagnostics().errors() {
        println!("{}", err);
    }

    println!();

    println!("note: this decision was due to the following policies:");
    for reason in ans.diagnostics().reason() {
        println!("  {}", reason);
    }
    println!();
}

/// This uses the waterford API to call the authorization engine.
fn execute_query(request: &Request, policies: PolicySet, entities: Entities) -> Response {
    let authorizer = Authorizer::new();
    authorizer.is_authorized(request, &policies, &entities)
}

fn validate<'a>(src: &'a str, sc: &'a str) -> &'a str {
    let p = PolicySet::from_str(src).unwrap();
    let schema = Schema::from_str(sc).unwrap();
    let validator = Validator::new(schema);
    let result = Validator::validate(&validator, &p, ValidationMode::default());
    if ValidationResult::validation_passed(&result) {
        "PASS"
    } else {
        let e = ValidationResult::validation_errors(&result);
        for err in e {
            println!("{}", err);
        }
        "FAIL"
    }
}
