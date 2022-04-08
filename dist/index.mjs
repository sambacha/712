import { utils } from 'ethers';
import BN from 'bn.js';

var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};
const EIP712DomainType = [
  {
    name: "name",
    type: "string"
  },
  {
    name: "version",
    type: "string"
  },
  {
    name: "chainId",
    type: "uint256"
  },
  {
    name: "verifyingContract",
    type: "address"
  }
];
const B32Z = "0x0000000000000000000000000000000000000000000000000000000000000000";
class EIP712Signer {
  constructor(domain, ...types) {
    this.structs = {
      EIP712Domain: EIP712DomainType
    };
    this.domain = {
      name: "",
      version: "",
      verifyingContract: "",
      chainId: 0
    };
    this.REQUIRED_FIELDS = [
      "domain",
      "types",
      "message",
      "primaryType"
    ];
    this._setDomain(domain);
    for (const type of types) {
      this._addType(type[0], type[1]);
    }
  }
  _addType(name, struct) {
    if (this.structs[name] !== void 0) {
      throw new Error(`Type already exists ${name}`);
    }
    this.structs[name] = struct;
  }
  _setDomain(domain) {
    this.domain = domain;
  }
  _encodeDataTypeField(type, value) {
    if (this.structs[type]) {
      return ["bytes32", value === null ? B32Z : this._hashData(type, value)];
    }
    if (type === "bytes") {
      return ["bytes32", utils.keccak256(value)];
    }
    if (type === "string") {
      return ["bytes32", utils.keccak256(Buffer.from(value, "utf8"))];
    }
    if (type === "uint256") {
      if (typeof value === "object") {
        value = value.toString();
      }
    }
    if (type.lastIndexOf("[]") === type.length - 2) {
      const extracted_type = type.slice(0, type.lastIndexOf("[]"));
      const encoded_array = value.map((elem) => this._encodeDataTypeField(extracted_type, elem));
      const abie = new utils.AbiCoder();
      return [
        "bytes32",
        utils.keccak256(abie.encode(encoded_array.map((elem) => elem[0]), encoded_array.map((elem) => elem[1])))
      ];
    }
    return [type, value];
  }
  _encodeData(name, payload) {
    const encodedTypes = ["bytes32"];
    const encodedData = [this._hashType(name)];
    for (const field of this.structs[name]) {
      if (payload[field.name] === void 0) {
        throw new Error(`Invalid Payload: at type ${name}, missing field ${field.name}`);
      }
      const field_res = this._encodeDataTypeField(field.type, payload[field.name]);
      encodedTypes.push(field_res[0]);
      encodedData.push(field_res[1]);
    }
    const abie = new utils.AbiCoder();
    return abie.encode(encodedTypes, encodedData);
  }
  _hashData(type, data) {
    return utils.keccak256(this._encodeData(type, data));
  }
  _getDependenciesOf(type, met = {}) {
    let result = [];
    if (type.lastIndexOf("[]") === type.length - 2) {
      return this._getDependenciesOf(type.slice(0, type.lastIndexOf("[]")), met);
    }
    if (met[type] === true || this.structs[type] === void 0)
      return result;
    result.push(type);
    met[type] = true;
    for (const field of this.structs[type]) {
      result = result.concat(this._getDependenciesOf(field.type, met));
    }
    return result;
  }
  _encodeType(type) {
    let result = "";
    let dependencies = this._getDependenciesOf(type).filter((dep) => dep !== type).sort();
    dependencies = [type].concat(dependencies);
    for (const t of dependencies) {
      result += `${t}(${this.structs[t].map((struct) => `${struct.type} ${struct.name}`).join(",")})`;
    }
    return result;
  }
  _hashType(type) {
    return utils.keccak256(Buffer.from(this._encodeType(type)));
  }
  _verifyTypes(payload) {
    const primary_type_dependencies = this._getDependenciesOf(payload.primaryType);
    const required_types = {
      EIP712Domain: this.structs["EIP712Domain"]
    };
    for (const dep of primary_type_dependencies) {
      required_types[dep] = this.structs[dep];
    }
    if (Object.keys(payload.types).length !== Object.keys(required_types).length) {
      throw new Error(`Invalid Types in given payload: got ${Object.keys(payload.types)}, expect ${Object.keys(required_types)}`);
    }
    for (const type of Object.keys(payload.types)) {
      if (!this.structs[type])
        throw new Error(`Unknown type ${type}`);
      const current_type = payload.types[type];
      const registered_current_type = this.structs[type];
      for (const field of current_type) {
        const eq_idx = registered_current_type.findIndex((eq_field) => eq_field.name === field.name);
        if (eq_idx === -1)
          throw new Error(`Error in ${type} type: unknwon field with name ${field.name}`);
        if (field.type !== registered_current_type[eq_idx].type)
          throw new Error(`Error in ${type} type: mismatch in field types: got ${field.type}, expected ${registered_current_type[eq_idx].type}`);
      }
    }
  }
  _verifyDomain(payload) {
    for (const field of this.structs["EIP712Domain"]) {
      if (payload.domain[field.name] === void 0)
        throw new Error(`Missing field in domain: ${field.name}`);
    }
  }
  _verifyPrimaryType(payload) {
    if (!this.structs[payload.primaryType]) {
      throw new Error(`Invalid primary type ${payload.primaryType}: unknown type`);
    }
  }
  _verifyMainPayloadField(payload) {
    if (Object.keys(payload).length !== this.REQUIRED_FIELDS.length) {
      throw new Error(`Invalid payload: has fields ${Object.keys(payload)}, should have ${this.REQUIRED_FIELDS}`);
    }
    for (const req of this.REQUIRED_FIELDS) {
      if (!Object.keys(payload).includes(req)) {
        throw new Error(`Missing ${req} field in payload`);
      }
    }
  }
  _fromSigned(num) {
    return new BN(Buffer.from(num.slice(2), "hex")).fromTwos(256);
  }
  _toUnsigned(num) {
    return Buffer.from(num.toTwos(256).toArray());
  }
  static _padWithZeroes(toPad, length) {
    let myString = "" + toPad;
    while (myString.length < length) {
      myString = "0" + myString;
    }
    return myString;
  }
  verifyPayload(payload) {
    this._verifyMainPayloadField(payload);
    this._verifyTypes(payload);
    this._verifyDomain(payload);
    this._verifyPrimaryType(payload);
    void this.encode(payload);
  }
  encode(payload, verify = false) {
    this._verifyMainPayloadField(payload);
    if (verify) {
      this._verifyTypes(payload);
      this._verifyDomain(payload);
      this._verifyPrimaryType(payload);
    }
    const result = [Buffer.from("1901", "hex")];
    result.push(Buffer.from(this._hashData("EIP712Domain", payload.domain).slice(2), "hex"));
    if (payload.primaryType !== "EIP712Domain") {
      result.push(Buffer.from(this._hashData(payload.primaryType, payload.message).slice(2), "hex"));
    }
    return `0x${Buffer.concat(result).toString("hex")}`;
  }
  sign(privateKey, payload, verify = false) {
    return __async(this, null, function* () {
      const encoded_payload = this.encode(payload, verify);
      switch (typeof privateKey) {
        case "string": {
          const sk = new utils.SigningKey(privateKey);
          const hashed_payload = utils.keccak256(Buffer.from(encoded_payload.slice(2), "hex"));
          const signature = sk.signDigest(Buffer.from(hashed_payload.slice(2), "hex"));
          const rSig = this._fromSigned(signature.r);
          const sSig = this._fromSigned(signature.s);
          const vSig = signature.v;
          const rStr = EIP712Signer._padWithZeroes(this._toUnsigned(rSig).toString("hex"), 64);
          const sStr = EIP712Signer._padWithZeroes(this._toUnsigned(sSig).toString("hex"), 64);
          const vStr = vSig.toString(16);
          return {
            hex: `0x${rStr}${sStr}${vStr}`,
            v: vSig,
            r: rStr,
            s: sStr
          };
        }
        case "function": {
          return privateKey(encoded_payload);
        }
      }
    });
  }
  verify(payload, signature, verify = false) {
    return __async(this, null, function* () {
      const encoded_payload = this.encode(payload, verify);
      const hashed_payload = utils.keccak256(Buffer.from(encoded_payload.slice(2), "hex"));
      return utils.recoverAddress(Buffer.from(hashed_payload.slice(2), "hex"), signature);
    });
  }
  generatePayload(data, primaryType) {
    const dependencies = this._getDependenciesOf(primaryType);
    const types = {};
    for (const dep of dependencies) {
      types[dep] = this.structs[dep];
    }
    types["EIP712Domain"] = this.structs["EIP712Domain"];
    return {
      domain: this.domain,
      primaryType,
      types,
      message: data
    };
  }
}

export { EIP712DomainType, EIP712Signer };
//# sourceMappingURL=index.mjs.map
