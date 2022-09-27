/* -------------------------------------------------------------------------- *\
 *             Apache 2.0 License Copyright © 2022 The Aurae Authors          *
 *                                                                            *
 *                +--------------------------------------------+              *
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 *                                                                            *
 * -------------------------------------------------------------------------- *
 *                                                                            *
 *   Licensed under the Apache License, Version 2.0 (the "License");          *
 *   you may not use this file except in compliance with the License.         *
 *   You may obtain a copy of the License at                                  *
 *                                                                            *
 *       http://www.apache.org/licenses/LICENSE-2.0                           *
 *                                                                            *
 *   Unless required by applicable law or agreed to in writing, software      *
 *   distributed under the License is distributed on an "AS IS" BASIS,        *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. *
 *   See the License for the specific language governing permissions and      *
 *   limitations under the License.                                           *
 *                                                                            *
\* -------------------------------------------------------------------------- */

extern crate core;

use std::process::Command;
use std::{fs, str};

use crate::SomeError::FailedToRunOpenssl;

trait AuthenticatorTrait {
    fn get_ca(&mut self) -> Result<Vec<u8>, SomeError>;
    fn get_workload_certificate(
        &mut self,
        name: &str,
    ) -> Result<Vec<u8>, SomeError>;
}

struct Authenticator {
    ca: Vec<u8>,
    root_dir: String,
}

impl AuthenticatorTrait for Authenticator {
    fn get_ca(&mut self) -> Result<Vec<u8>, SomeError> {
        let my_dir = env!("PWD");
        let ca_crt = format!("{}{}", &my_dir, "/pki/ca.crt");
        // fetch ca crt
        self.ca = match fs::read(ca_crt) {
            Ok(cert) => cert,
            Err(_) => {
                vec![]
            }
        };

        // if neither exists, create
        match self.ca.len() {
            0 => {
                println!("no CA found, generating...");
                self.ca = match generate_root_ca(self.root_dir.to_owned()) {
                    Ok(cert) => cert,
                    err => return err,
                };
                println!("CA generated");
            }
            key_size if key_size > 0 => {
                println!("found CA, reusing...");
                // do nothing
            }
            _ => {
                return Err(FailedToRunOpenssl);
            }
        }

        let mut res: Vec<u8> = Vec::with_capacity(*&self.ca.len());

        // should be ok, since we set the capacity
        unsafe {
            res.set_len(*&self.ca.len());
        }

        res.copy_from_slice(&self.ca);
        Ok(res)
    }

    fn get_workload_certificate(
        &mut self,
        name: &str,
    ) -> Result<Vec<u8>, SomeError> {
        match self.ca.len() {
            0 => {}
            _ => {}
        }
        match generate_certificate_request(&name) {
            Ok(_) => {
                println!("CSR generated")
            }
            _ => return Err(FailedToRunOpenssl),
        }
        sign_server_certificate(&name)
    }
}

fn start(root_dir: &str) -> Result<Authenticator, SomeError> {
    let mut authenticator = Authenticator { ca: vec![], root_dir: root_dir.to_owned() };

    match authenticator.get_ca() {
        Ok(_) => Ok(authenticator),
        Err(err) => Err(err),
    }
}

pub enum SomeError {
    FailedToRunOpenssl,
}

fn generate_root_ca(my_dir: String) -> Result<Vec<u8>, SomeError> {
    let ca_crt = format!("{}{}", &my_dir, "/pki/ca.crt");
    let ca_key = format!("{}{}", &my_dir, "/pki/ca.key");
    let output = Command::new("openssl")
        .arg("req")
        .arg("-new")
        .arg("-x509")
        .arg("-nodes")
        .args(["-days", "9999"])
        .args(["-addext", "subjectAltName = DNS:unsafe.aurae.io"])
        .args([
            "-subj",
            "/C=IS/ST=aurae/L=aurae/O=Aurae/OU=Runtime/CN=unsafe.aurae.io",
        ])
        .args(["-keyout", &ca_key])
        .args(["-out", &ca_crt])
        .output()
        .expect("failed to execute process");

    println!("{}", env!("PWD"));

    match output.status.code() {
        Some(0) => { /* carry on */ }
        Some(_) => {
            return match str::from_utf8(&output.stderr) {
                Ok(_) => Err(FailedToRunOpenssl),
                Err(_) => Err(FailedToRunOpenssl),
            };
        }
        None => return Err(FailedToRunOpenssl),
    }

    println!("exit status: {}", output.status);
    let b = match str::from_utf8(&output.stderr) {
        Ok(b) => b,
        Err(_) => return Err(FailedToRunOpenssl),
    };
    println!("exit status: {:?}", String::from(b));

    let server_root_ca_cert = fs::read_to_string(&ca_crt)
        .expect("Should have been able to read the file");

    return Ok(server_root_ca_cert.as_bytes().to_vec());
}

// openssl req \
//   -new \
//   -subj    "/C=IS/ST=aurae/L=aurae/O=Aurae/OU=Runtime/CN=server.unsafe.aurae.io" \
//   -addext "subjectAltName = DNS:server.unsafe.aurae.io" \
//   -key    "./pki/server.key" \
//   -out    "./pki/server.csr" 2>/dev/null
fn generate_certificate_request(name: &str) -> Result<(), SomeError> {
    println!("Attempting to generate CSR for: {}", &name);
    // TODO validate name only has certain characters valid for url
    let my_dir = env!("PWD");

    let cert_key_path = format!("{}/pki/{}.server.key", &my_dir, &name);
    let csr_path = format!("{}/pki/{}.server.csr", &my_dir, &name);

    println!("{}", &csr_path);
    println!("{}", &cert_key_path);
    // TODO validate ca_crt and ca_key are in PWD
    // openssl genrsa -out ./pki/server.key 4096 2>/dev/null
    let output = Command::new("openssl")
        .arg("genrsa")
        .args(["-out", &cert_key_path])
        .arg("4096")
        .output()
        .expect("failed to execute process");

    match output.status.code() {
        Some(0) => { /* carry on */ }
        Some(_) => {
            let b = match str::from_utf8(&output.stderr) {
                Ok(b) => b,
                Err(_) => return Err(FailedToRunOpenssl),
            };
            println!("exit status: {:?}", String::from(b));
            return Err(FailedToRunOpenssl);
        }
        _ => return Err(FailedToRunOpenssl),
    };

    let alt_name = format!("subjectAltName = DNS:{}.unsafe.aurae.io", &name);
    let output = Command::new("openssl")
        .arg("req")
        .arg("-new")
        .args(["-subj", "/C=IS/ST=aurae/L=aurae/O=Aurae/OU=Runtime/CN=server.unsafe.aurae.io"])
        .args(["-addext", alt_name.as_str()])
        .args(["-key", &cert_key_path])
        .args(["-out", &csr_path])
        .output()
        .expect("failed to execute process");

    match output.status.code() {
        Some(0) => { /* carry on */ }
        Some(_) => {
            let b = match str::from_utf8(&output.stderr) {
                Ok(b) => b,
                Err(_) => return Err(FailedToRunOpenssl),
            };
            println!("exit status: {:?}", String::from(b));
            return Err(FailedToRunOpenssl);
        }
        _ => return Err(FailedToRunOpenssl),
    };

    let output = Command::new("openssl")
        .arg("req")
        .arg("-new")
        .args(["-subj", "/C=IS/ST=aurae/L=aurae/O=Aurae/OU=Runtime/CN=server.unsafe.aurae.io"])
        .args(["-addext", "subjectAltName = DNS:server.unsafe.aurae.io"])
        .args(["-key", &cert_key_path])
        .args(["-out", &csr_path])
        .output()
        .expect("failed to execute process");

    match output.status.code() {
        Some(0) => { /* carry on */ }
        Some(_) => {
            let b = match str::from_utf8(&output.stderr) {
                Ok(b) => b,
                Err(_) => return Err(FailedToRunOpenssl),
            };
            println!("exit status: {:?}", String::from(b));
            return Err(FailedToRunOpenssl);
        }
        _ => return Err(FailedToRunOpenssl),
    };

    return Ok(());
}

fn sign_server_certificate(name: &str) -> Result<Vec<u8>, SomeError> {
    // inputs
    let my_dir = env!("PWD");
    let ca_key_path = format!("{}/pki/ca.key", &my_dir);
    let ca_cert_path = format!("{}/pki/ca.crt", &my_dir);
    let csr_path = format!("{}/pki/{}.server.csr", &my_dir, &name);

    // intermediate data
    let client_ext_path = format!("{}/hack/certgen.client.ext", &my_dir);
    let server_ext_path = format!("{}/hack/certgen.server.ext", &my_dir);

    // output path
    let signed_cert_path =
        format!("{}/pki/_unsafe.{}.server.crt", &my_dir, &name);

    let output = Command::new("openssl")
        .arg("x509")
        .arg("-req")
        .args(["-days", "9999"])
        // TODO Why client.ext instead of server.ext? maybe a bug in hack script.
        //      reproducing for now, will look into this later
        .args(["-extfile", &client_ext_path])
        .args(["-in", &csr_path])
        .args(["-CA", &ca_cert_path])
        .args(["-CAkey", &ca_key_path])
        .arg("-CAcreateserial")
        // TODO Why twice?
        .args(["-extfile", &server_ext_path])
        .args(["-out", &signed_cert_path])
        .output()
        .expect("failed to execute process");

    match output.status.code() {
        Some(0) => { /* carry on */ }
        Some(_) => {
            let b = match str::from_utf8(&output.stderr) {
                Ok(b) => b,
                Err(_) => return Err(FailedToRunOpenssl),
            };
            println!("exit status: {:?}", String::from(b));
            return Err(FailedToRunOpenssl);
        }
        _ => return Err(FailedToRunOpenssl),
    };
    let res = fs::read_to_string(&signed_cert_path)
        .expect("Should have been able to read the file");

    return Ok(res.as_bytes().to_vec());
}

mod tests {
    use crate::{
        generate_certificate_request, generate_root_ca, start,
        AuthenticatorTrait,
    };

    #[test]
    fn it_works() {
        assert_eq!(0, 0)
    }

    #[test]
    fn test_new_ca() {
        match generate_root_ca(env!("PWD").to_owned()) {
            Ok(x) => {
                println!("ca:\n{:#?}", x)
            }
            Err(_) => {
                println!("nothing")
            }
        };
    }

    #[test]
    fn test_generate_certificate_request() {
        match generate_certificate_request("name") {
            Ok(x) => {
                println!("ca:\n{:#?}", x)
            }
            Err(_) => {
                println!("nothing")
            }
        };
    }

    #[test]
    fn test_workflow() {
        match start(env!("PWD")) {
            Ok(mut authenticator) => {
                match authenticator.get_workload_certificate("hello") {
                    Ok(cert) => {
                        assert_eq!(cert.len() > 0, true)
                    }
                    Err(_) => {
                        panic!(
                            "unexpected error generating workload certificate"
                        )
                    }
                };
            }
            Err(_) => {
                panic!("start failed")
            }
        }
    }
}
