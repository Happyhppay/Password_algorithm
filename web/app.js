const algorithms = {
  AES: {
    label: "AES-128",
    kind: "对称加密",
    hint: "CBC/ECB，加解密与块操作",
    operations: ["encrypt", "decrypt", "encrypt_block", "decrypt_block"],
    defaults: {
      operation: "encrypt",
      data: "北邮信息安全",
      key: "00112233445566778899aabbccddeeff",
      key_format: "hex",
      iv: "00000000000000000000000000000000",
      iv_format: "hex",
      mode: "CBC",
      output_format: "hex"
    }
  },
  SM4: {
    label: "SM4",
    kind: "对称加密",
    hint: "国密分组密码，CBC/ECB",
    operations: ["encrypt", "decrypt", "encrypt_block", "decrypt_block"],
    defaults: {
      operation: "encrypt_block",
      data: "0123456789abcdeffedcba9876543210",
      data_format: "hex",
      key: "0123456789abcdeffedcba9876543210",
      key_format: "hex",
      output_format: "hex"
    }
  },
  RC6: {
    label: "RC6",
    kind: "对称加密",
    hint: "RC6-32/20/16",
    operations: ["encrypt", "decrypt", "encrypt_block", "decrypt_block"],
    defaults: {
      operation: "encrypt",
      data: "assignment message",
      key: "00112233445566778899aabbccddeeff",
      key_format: "hex",
      mode: "CBC",
      iv: "00000000000000000000000000000000",
      iv_format: "hex",
      output_format: "hex"
    }
  },
  SHA1: {
    label: "SHA1",
    kind: "哈希",
    hint: "输出十六进制摘要",
    operations: ["digest"],
    defaults: { operation: "digest", data: "abc" }
  },
  SHA256: {
    label: "SHA256",
    kind: "哈希",
    hint: "输出十六进制摘要",
    operations: ["digest"],
    defaults: { operation: "digest", data: "abc" }
  },
  SHA3: {
    label: "SHA3-256",
    kind: "哈希",
    hint: "输出十六进制摘要",
    operations: ["digest"],
    defaults: { operation: "digest", data: "abc" }
  },
  RIPEMD160: {
    label: "RIPEMD160",
    kind: "哈希",
    hint: "输出十六进制摘要",
    operations: ["digest"],
    defaults: { operation: "digest", data: "abc" }
  },
  HmacSHA1: {
    label: "HMAC-SHA1",
    kind: "消息认证",
    hint: "需要 key 与 data",
    operations: ["digest"],
    defaults: { operation: "digest", data: "abc", key: "secret" }
  },
  HmacSHA256: {
    label: "HMAC-SHA256",
    kind: "消息认证",
    hint: "需要 key 与 data",
    operations: ["digest"],
    defaults: { operation: "digest", data: "abc", key: "secret" }
  },
  PBKDF2: {
    label: "PBKDF2",
    kind: "口令派生",
    hint: "password + salt + iterations",
    operations: ["derive"],
    defaults: { operation: "derive", password: "password", salt: "salt", iterations: 1000, dklen: 32, hash: "sha256" }
  },
  Base64: {
    label: "Base64",
    kind: "编码",
    hint: "编码或解码",
    operations: ["encode", "decode"],
    defaults: { operation: "encode", data: "hello" }
  },
  "UTF-8": {
    label: "UTF-8",
    kind: "编码",
    hint: "文本与 UTF-8 字节",
    operations: ["encode", "decode"],
    defaults: { operation: "encode", data: "密码" }
  },
  RSA: {
    label: "RSA-1024bit",
    backend: "RSA",
    kind: "公钥密码",
    hint: "1024 bit 密钥生成与加解密",
    operations: ["generate_keypair", "encrypt", "decrypt"],
    defaults: { operation: "generate_keypair", bits: 1024, data: "assignment message" }
  },
  "RSA-SHA1": {
    label: "RSA-SHA1",
    backend: "RSA-SHA1",
    kind: "公钥密码",
    hint: "RSA + SHA1 数字签名与验签",
    operations: ["generate_keypair", "sign", "verify"],
    defaults: { operation: "generate_keypair", bits: 1024, data: "assignment message", output_format: "hex" }
  },
  ECC: {
    label: "ECC-160bit",
    backend: "ECC",
    kind: "公钥密码",
    hint: "secp160r1 密钥生成与 ECDH 共享密钥",
    operations: ["generate_keypair", "ecdh"],
    defaults: { operation: "generate_keypair" }
  },
  ECDSA: {
    label: "ECDSA",
    backend: "ECDSA",
    kind: "公钥密码",
    hint: "基于 ECC-160 secp160r1 的签名验签",
    operations: ["generate_keypair", "sign", "verify"],
    defaults: { operation: "generate_keypair", data: "assignment message", hash: "sha1" }
  }
};

const samples = {
  AES: {
    encrypt: {
      CBC: {
        data: "assignment message",
        data_format: "text",
        key: "00112233445566778899aabbccddeeff",
        key_format: "hex",
        iv: "00000000000000000000000000000000",
        iv_format: "hex",
        mode: "CBC",
        output_format: "hex"
      },
      ECB: {
        data: "assignment message",
        data_format: "text",
        key: "00112233445566778899aabbccddeeff",
        key_format: "hex",
        mode: "ECB",
        output_format: "hex"
      }
    },
    decrypt: {
      CBC: {
        data: "b60eb4a0cce080b4d0e0d4d227c9abc554a3a24fb29f418d8bc49199817a17e7",
        data_format: "hex",
        key: "00112233445566778899aabbccddeeff",
        key_format: "hex",
        iv: "00000000000000000000000000000000",
        iv_format: "hex",
        mode: "CBC",
        output_format: "text"
      },
      ECB: {
        data: "b60eb4a0cce080b4d0e0d4d227c9abc559b70671ecc8871f7b3ce8d8e069885d",
        data_format: "hex",
        key: "00112233445566778899aabbccddeeff",
        key_format: "hex",
        mode: "ECB",
        output_format: "text"
      }
    },
    encrypt_block: {
      data: "00112233445566778899aabbccddeeff",
      data_format: "hex",
      key: "000102030405060708090a0b0c0d0e0f",
      key_format: "hex",
      output_format: "hex"
    },
    decrypt_block: {
      data: "69c4e0d86a7b0430d8cdb78070b4c55a",
      data_format: "hex",
      key: "000102030405060708090a0b0c0d0e0f",
      key_format: "hex",
      output_format: "hex"
    }
  },
  SM4: {
    encrypt: {
      CBC: {
        data: "assignment message",
        data_format: "text",
        key: "0123456789abcdeffedcba9876543210",
        key_format: "hex",
        iv: "00000000000000000000000000000000",
        iv_format: "hex",
        mode: "CBC",
        output_format: "hex"
      },
      ECB: {
        data: "assignment message",
        data_format: "text",
        key: "0123456789abcdeffedcba9876543210",
        key_format: "hex",
        mode: "ECB",
        output_format: "hex"
      }
    },
    decrypt: {
      CBC: {
        data: "a474d9a1967d0c837bd259dd3d73d28b106a096ac7d11e7022e2a0f5f7652ade",
        data_format: "hex",
        key: "0123456789abcdeffedcba9876543210",
        key_format: "hex",
        iv: "00000000000000000000000000000000",
        iv_format: "hex",
        mode: "CBC",
        output_format: "text"
      },
      ECB: {
        data: "a474d9a1967d0c837bd259dd3d73d28bb75c13b6d81d62292e568dad6dc3ba3d",
        data_format: "hex",
        key: "0123456789abcdeffedcba9876543210",
        key_format: "hex",
        mode: "ECB",
        output_format: "text"
      }
    },
    encrypt_block: {
      data: "0123456789abcdeffedcba9876543210",
      data_format: "hex",
      key: "0123456789abcdeffedcba9876543210",
      key_format: "hex",
      output_format: "hex"
    },
    decrypt_block: {
      data: "681edf34d206965e86b3e94f536e4246",
      data_format: "hex",
      key: "0123456789abcdeffedcba9876543210",
      key_format: "hex",
      output_format: "hex"
    }
  },
  RC6: {
    encrypt: {
      CBC: {
        data: "assignment message",
        data_format: "text",
        key: "00112233445566778899aabbccddeeff",
        key_format: "hex",
        iv: "00000000000000000000000000000000",
        iv_format: "hex",
        mode: "CBC",
        output_format: "hex"
      },
      ECB: {
        data: "assignment message",
        data_format: "text",
        key: "00112233445566778899aabbccddeeff",
        key_format: "hex",
        mode: "ECB",
        output_format: "hex"
      }
    },
    decrypt: {
      CBC: {
        data: "4bea59323134a7909cb611f76b22878784ab179773399f4078fa17b5be2070ab",
        data_format: "hex",
        key: "00112233445566778899aabbccddeeff",
        key_format: "hex",
        iv: "00000000000000000000000000000000",
        iv_format: "hex",
        mode: "CBC",
        output_format: "text"
      },
      ECB: {
        data: "4bea59323134a7909cb611f76b22878749495392dcd7761d6220ad2907724be7",
        data_format: "hex",
        key: "00112233445566778899aabbccddeeff",
        key_format: "hex",
        mode: "ECB",
        output_format: "text"
      }
    },
    encrypt_block: {
      data: "00000000000000000000000000000000",
      data_format: "hex",
      key: "00000000000000000000000000000000",
      key_format: "hex",
      output_format: "hex"
    },
    decrypt_block: {
      data: "8fc3a53656b1f778c129df4e9848a41e",
      data_format: "hex",
      key: "00000000000000000000000000000000",
      key_format: "hex",
      output_format: "hex"
    }
  },
  Base64: {
    encode: { data: "hello", data_format: "text", output_format: "text" },
    decode: { data: "aGVsbG8=", output_format: "text" }
  },
  "UTF-8": {
    encode: { data: "密码" },
    decode: { data: "e5af86e7a081", data_format: "hex" }
  },
  RSA: {
    generate_keypair: { bits: 1024 },
    encrypt: {
      data: "assignment message",
      data_format: "text",
      public_key:
        '{"n":"0x96bf9cd7bd7d016cebf53ff27c9b0ec728a69fc5a1742ca13bf9c14ea81b1987121c23e7a6039a52d8d38e7c0b22377cf3e88c8ed24af50f44603979e56e3d1c8e5b24ac23e42fa93229ebeaf6a3784e7d3f4796adf7a41809c9131651249bf5c61db32b9016c89b14a02cb9ace303a12954659a7435e36d669c93738d20ed9d","e":65537}',
      output_format: "hex"
    },
    decrypt: {
      data:
        "7574f1ac7b4821ed104d38b13cfa87368c1e605297496633e2da1e0c3e14721b6933ae51aabc7fcfe8d121b48e4eca01e5e52456532a97679d662729759cfb0dbcc7f4a4d1d03a303066bbc01bd0938429505cb5c3f617ff7f4022d26f789f27db8dafe3a630c2532b6eba679f5dec4be84f69b1b826d07a65e283affb2517e3",
      data_format: "hex",
      private_key:
        '{"n":"0x96bf9cd7bd7d016cebf53ff27c9b0ec728a69fc5a1742ca13bf9c14ea81b1987121c23e7a6039a52d8d38e7c0b22377cf3e88c8ed24af50f44603979e56e3d1c8e5b24ac23e42fa93229ebeaf6a3784e7d3f4796adf7a41809c9131651249bf5c61db32b9016c89b14a02cb9ace303a12954659a7435e36d669c93738d20ed9d","e":65537,"d":"0x960c03417a0a82f0b7ac550a379cdf08bd1d9cca49fa28b213d074e8a5cad38dee28b4544e9a27716f00a4423392cb48443ea4294487f7844ababc7ae832e1ff8f43675ae46a17b3d843edfda9479efdb8400677dac970a8263f75c6129bb079f289353824f6370ad1c4a409c76db07df8f8caf9c2bd791890d0814d3421ced","p":"0xe31306ace1466fb5fd620088287cc699d59ae9d9746ff212853dae96d2054e9abc0e30bb082427b9815e3a13d0b998b1e48f10d5ce876400a768b99db90a9eeb","q":"0xa9f392fbe2d707daa7a88fe490f8c2e3b84a642cfcfe83ace4659b9b67e1f16836b15ae0325ea5259b3bf5bb19eb493b95eef23d16fdd1c88242690223455397"}',
      output_format: "text"
    }
  },
  "RSA-SHA1": {
    generate_keypair: { bits: 1024 },
    sign: {
      data: "assignment message",
      data_format: "text",
      private_key:
        '{"n":"0x96bf9cd7bd7d016cebf53ff27c9b0ec728a69fc5a1742ca13bf9c14ea81b1987121c23e7a6039a52d8d38e7c0b22377cf3e88c8ed24af50f44603979e56e3d1c8e5b24ac23e42fa93229ebeaf6a3784e7d3f4796adf7a41809c9131651249bf5c61db32b9016c89b14a02cb9ace303a12954659a7435e36d669c93738d20ed9d","e":65537,"d":"0x960c03417a0a82f0b7ac550a379cdf08bd1d9cca49fa28b213d074e8a5cad38dee28b4544e9a27716f00a4423392cb48443ea4294487f7844ababc7ae832e1ff8f43675ae46a17b3d843edfda9479efdb8400677dac970a8263f75c6129bb079f289353824f6370ad1c4a409c76db07df8f8caf9c2bd791890d0814d3421ced","p":"0xe31306ace1466fb5fd620088287cc699d59ae9d9746ff212853dae96d2054e9abc0e30bb082427b9815e3a13d0b998b1e48f10d5ce876400a768b99db90a9eeb","q":"0xa9f392fbe2d707daa7a88fe490f8c2e3b84a642cfcfe83ace4659b9b67e1f16836b15ae0325ea5259b3bf5bb19eb493b95eef23d16fdd1c88242690223455397"}',
      output_format: "hex"
    },
    verify: {
      data: "assignment message",
      data_format: "text",
      public_key:
        '{"n":"0x96bf9cd7bd7d016cebf53ff27c9b0ec728a69fc5a1742ca13bf9c14ea81b1987121c23e7a6039a52d8d38e7c0b22377cf3e88c8ed24af50f44603979e56e3d1c8e5b24ac23e42fa93229ebeaf6a3784e7d3f4796adf7a41809c9131651249bf5c61db32b9016c89b14a02cb9ace303a12954659a7435e36d669c93738d20ed9d","e":65537}',
      signature:
        "200a8421f4666f578f46ac0762b72c26e61feacfbdfc821db7f463595e594a6acf34ba18927b493f8d286e0efe636276eb0d71e798600d0b41be81fe1ad351a0aa8898ffbeaaae58233a2ae8db4a66b67f8aedbe8bba85a5af536c4346e27e598b46e3432d24c62fb170d64894174b42686ccadf1f57a173ee5a84c71f546895",
      signature_format: "hex"
    }
  },
  ECC: {
    generate_keypair: {},
    ecdh: {
      private_key: '{"curve":"secp160r1","d":"0x123456789abcdef123456789abcdef123456789a"}',
      public_key:
        '{"curve":"secp160r1","x":"0x997edde7239dfb8cf56c5fc38c2c412faa49e348","y":"0x3307f50b1366f5cfc6c4fd68bdce72bce4524501"}'
    }
  },
  ECDSA: {
    generate_keypair: {},
    sign: {
      data: "assignment message",
      data_format: "text",
      private_key: '{"curve":"secp160r1","d":"0x123456789abcdef123456789abcdef123456789a"}',
      hash: "sha1"
    },
    verify: {
      data: "assignment message",
      data_format: "text",
      public_key:
        '{"curve":"secp160r1","x":"0x7ea734d2e3493b4e1b9f41ca500c742490a0db76","y":"0x99bdd6edff8c9dd030d7c793328abb7fa507654b"}',
      signature: '{"r":"0xb0c6fb3d1c949e42f839897a3296e9e8b1c8467","s":"0x2f730e8fe2593d7ad6c6a8d3d485fc1e4da5f901"}',
      hash: "sha1"
    }
  }
};

const fieldDefinitions = {
  data: { label: "data", type: "textarea", wide: true, help: "明文、密文或待摘要内容。" },
  data_format: { label: "data_format", type: "select", options: ["text", "hex", "base64"], help: "输入 data 的格式。" },
  key: { label: "key", type: "input", help: "AES/SM4 需要 16 字节；HMAC 可使用任意文本 key。" },
  key_format: { label: "key_format", type: "select", options: ["text", "hex", "base64"] },
  iv: { label: "iv", type: "input", help: "CBC 模式使用，16 字节。" },
  iv_format: { label: "iv_format", type: "select", options: ["text", "hex", "base64"] },
  mode: { label: "mode", type: "select", options: ["CBC", "ECB"] },
  output_format: { label: "output_format", type: "select", options: ["hex", "text", "base64"] },
  password: { label: "password", type: "input" },
  salt: { label: "salt", type: "input" },
  iterations: { label: "iterations", type: "number" },
  dklen: { label: "dklen", type: "number" },
  hash: { label: "hash", type: "select", options: ["sha1", "sha256"] },
  bits: { label: "bits", type: "number" },
  public_key: { label: "public_key", type: "textarea", wide: true, help: "粘贴 generate_keypair 返回的 public_key JSON。" },
  private_key: { label: "private_key", type: "textarea", wide: true, help: "粘贴 generate_keypair 返回的 private_key JSON。" },
  signature: { label: "signature", type: "textarea", wide: true, help: "RSA 使用十六进制签名；ECDSA 使用 {\"r\":\"0x...\",\"s\":\"0x...\"}。" },
  signature_format: { label: "signature_format", type: "select", options: ["hex", "text", "base64"] }
};

const fieldsByOperation = {
  symmetric: {
    encrypt: ["data", "data_format", "key", "key_format", "iv", "iv_format", "mode", "output_format"],
    decrypt: ["data", "data_format", "key", "key_format", "iv", "iv_format", "mode", "output_format"],
    encrypt_block: ["data", "data_format", "key", "key_format", "output_format"],
    decrypt_block: ["data", "data_format", "key", "key_format", "output_format"]
  },
  hash: {
    digest: ["data", "data_format"]
  },
  hmac: {
    digest: ["data", "data_format", "key", "key_format"]
  },
  pbkdf2: {
    derive: ["password", "salt", "iterations", "dklen", "hash"]
  },
  codec: {
    encode: ["data", "data_format", "output_format"],
    decode: ["data", "output_format"]
  },
  utf8: {
    encode: ["data"],
    decode: ["data", "data_format"]
  },
  rsa: {
    generate_keypair: ["bits"],
    encrypt: ["data", "data_format", "public_key", "output_format"],
    decrypt: ["data", "data_format", "private_key", "output_format"],
    sign: ["data", "data_format", "private_key", "output_format"],
    verify: ["data", "data_format", "public_key", "signature", "signature_format"]
  },
  ecc: {
    generate_keypair: [],
    sign: ["data", "data_format", "private_key", "hash"],
    verify: ["data", "data_format", "public_key", "signature", "hash"],
    ecdh: ["private_key", "public_key"]
  }
};

const algorithmEl = document.querySelector("#algorithm");
const operationEl = document.querySelector("#operation");
const formEl = document.querySelector("#cryptoForm");
const fieldsEl = document.querySelector("#dynamicFields");
const resultBox = document.querySelector("#resultBox");
const statusCode = document.querySelector("#statusCode");
const elapsedTime = document.querySelector("#elapsedTime");
const operationHint = document.querySelector("#operationHint");
const summaryEl = document.querySelector("#algorithmSummary");
const serverStatus = document.querySelector("#serverStatus");

function categoryFor(name) {
  if (["AES", "SM4", "RC6"].includes(name)) return "symmetric";
  if (["SHA1", "SHA256", "SHA3", "RIPEMD160"].includes(name)) return "hash";
  if (["HmacSHA1", "HmacSHA256"].includes(name)) return "hmac";
  if (name === "PBKDF2") return "pbkdf2";
  if (name === "Base64") return "codec";
  if (name === "UTF-8") return "utf8";
  if (["RSA", "RSA-SHA1"].includes(name)) return "rsa";
  return "ecc";
}

function option(text, value = text) {
  const node = document.createElement("option");
  node.value = value;
  node.textContent = text;
  return node;
}

function fillAlgorithms() {
  Object.entries(algorithms).forEach(([name, item]) => {
    algorithmEl.appendChild(option(item.label, name));
  });
}

function fillOperations() {
  const config = algorithms[algorithmEl.value];
  operationEl.replaceChildren(...config.operations.map((op) => option(op)));
  operationEl.value = config.defaults.operation || config.operations[0];
  operationHint.textContent = config.hint;
  renderSummary(config);
  renderFields();
}

function renderSummary(config) {
  const rows = [
    ["类别", config.kind],
    ["操作数", String(config.operations.length)],
    ["接口", "/api/call"]
  ];
  summaryEl.replaceChildren(
    ...rows.map(([label, value]) => {
      const item = document.createElement("div");
      item.className = "summary-item";
      item.innerHTML = `<span>${label}</span><strong>${value}</strong>`;
      return item;
    })
  );
}

function renderFields() {
  const name = algorithmEl.value;
  const op = operationEl.value;
  const category = categoryFor(name);
  const fieldNames = fieldsByOperation[category][op] || [];
  const sample = sampleFor(name, op, algorithms[name].defaults.mode);
  fieldsEl.replaceChildren(...fieldNames.map((field) => createField(field, sample[field])));
  const modeControl = formEl.elements.mode;
  if (modeControl) {
    modeControl.addEventListener("change", () => loadSample(false));
  }
}

function createField(name, value = "") {
  const def = fieldDefinitions[name];
  const wrap = document.createElement("div");
  wrap.className = `field-group${def.wide ? " field-wide" : ""}`;
  const label = document.createElement("label");
  label.htmlFor = `field-${name}`;
  label.textContent = def.label;
  let control;
  if (def.type === "textarea") {
    control = document.createElement("textarea");
  } else if (def.type === "select") {
    control = document.createElement("select");
    def.options.forEach((item) => control.appendChild(option(item)));
  } else {
    control = document.createElement("input");
    control.type = def.type || "text";
  }
  control.id = `field-${name}`;
  control.name = name;
  control.value = value ?? "";
  wrap.append(label, control);
  if (def.help) {
    const help = document.createElement("div");
    help.className = "help-text";
    help.textContent = def.help;
    wrap.appendChild(help);
  }
  return wrap;
}

function sampleFor(algorithm, operation, mode) {
  const algorithmSamples = samples[algorithm] || {};
  const operationSample = algorithmSamples[operation];
  if (operationSample) {
    if (operationSample.CBC || operationSample.ECB) {
      return { ...operationSample[mode || "CBC"] };
    }
    return { ...operationSample };
  }
  return { ...algorithms[algorithm].defaults, operation };
}

function loadSample(resetOperation = true) {
  const config = algorithms[algorithmEl.value];
  if (resetOperation && config.defaults.operation && config.operations.includes(config.defaults.operation)) {
    operationEl.value = config.defaults.operation;
    renderFields();
  }
  const currentMode = formEl.elements.mode?.value || config.defaults.mode || "CBC";
  const sample = sampleFor(algorithmEl.value, operationEl.value, currentMode);
  Object.entries(sample).forEach(([name, value]) => {
    const node = formEl.elements[name];
    if (node) node.value = value;
  });
}

function parseJsonField(value, label) {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`${label} 不是合法 JSON`);
  }
}

function collectParams() {
  const params = {};
  const formData = new FormData(formEl);
  for (const [name, value] of formData.entries()) {
    if (value === "") continue;
    if (["public_key", "private_key"].includes(name)) {
      params[name] = parseJsonField(value, name);
    } else if (name === "signature" && value.trim().startsWith("{")) {
      params[name] = parseJsonField(value, name);
    } else if (["iterations", "dklen", "bits"].includes(name)) {
      params[name] = Number(value);
    } else {
      params[name] = value;
    }
  }
  return params;
}

async function run() {
  const started = performance.now();
  statusCode.textContent = "status: running";
  statusCode.className = "";
  elapsedTime.textContent = "耗时: -";
  try {
    const payload = {
      algorithm: algorithms[algorithmEl.value].backend || algorithmEl.value,
      operation: operationEl.value,
      params: collectParams()
    };
    resultBox.textContent = JSON.stringify(payload, null, 2);
    const response = await fetch("/api/call", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    resultBox.textContent = JSON.stringify(data, null, 2);
    const ok = data.status === 0;
    statusCode.textContent = `status: ${data.status}`;
    statusCode.className = ok ? "ok" : "bad";
    serverStatus.textContent = ok ? "接口正常" : "接口返回错误";
  } catch (error) {
    resultBox.textContent = JSON.stringify({ status: 1, message: error.message, result: null }, null, 2);
    statusCode.textContent = "status: 1";
    statusCode.className = "bad";
    serverStatus.textContent = "请求失败";
  } finally {
    elapsedTime.textContent = `耗时: ${Math.round(performance.now() - started)} ms`;
  }
}

async function copyResult() {
  await navigator.clipboard.writeText(resultBox.textContent);
}

fillAlgorithms();
fillOperations();
loadSample();

algorithmEl.addEventListener("change", fillOperations);
operationEl.addEventListener("change", () => {
  renderFields();
  loadSample(false);
});
document.querySelector("#sampleBtn").addEventListener("click", () => loadSample(false));
document.querySelector("#runBtn").addEventListener("click", run);
document.querySelector("#copyBtn").addEventListener("click", copyResult);
