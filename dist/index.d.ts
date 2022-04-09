import BN from 'bn.js';

/**
 *
 * Field in a User Defined Types
 * @export
 * @interface EIP712StructField
 */
interface EIP712StructField {
    name: string;
    type: string;
}
/**
 * User Defined Types are just an array of the fields they contain
 */
declare type EIP712Struct = EIP712StructField[];
/**
 *
 *  Interface of the EIP712Domain structure
 * @export
 * @interface EIP712Domain
 */
interface EIP712Domain {
    name: string;
    version: string;
    chainId: number | BN;
    verifyingContract: string;
}
/**
 *
 *  Interface of the complete payload required for signing
 * @export
 * @interface EIP712Payload
 */
interface EIP712Payload {
    types: {
        [key: string]: EIP712Struct;
    };
    primaryType: string;
    message: any;
    domain: EIP712Domain;
}
interface EIP712Signature {
    hex: string;
    v: number;
    s: string;
    r: string;
}
/**
 * EIP712Domain Type, useful as it is always required inside the payload for the signature
 */
declare const EIP712DomainType: {
    name: string;
    type: string;
}[];
declare type ExternalSigner = (encodedPayload: string) => Promise<EIP712Signature>;
/**
 *
 * Helper class that takes types, domain and primary when built and is able to verify provided arguments, sign payload and verify signatures
 * This class should be extended by a custom class.
 * @export
 * @class EIP712Signer
 */
declare class EIP712Signer {
    /**
     * All types of current Signer
     */
    private readonly structs;
    /**
     * Mandatory domain structure
     */
    private domain;
    /**
     * Required for checks
     */
    private readonly REQUIRED_FIELDS;
    /**
     * Adds provided type to type list
     *
     * @param name Name of the type
     * @param struct Fields of the type
     * @private
     */
    private _addType;
    /**
     * Sets the domain (EIP712Domain) structure
     *
     * @param domain Domain structure
     * @private
     */
    private _setDomain;
    /**
     * Encodes a single field. Works by calling itself recursively for complexe types or arrays
     *
     * @param type Name of the given field
     * @param value Value of the given field
     * @private
     */
    private _encodeDataTypeField;
    /**
     * Encodes a type and all of its fields. Is often called recursively when dealing with structures inside structures ...
     *
     * @param name Name of the type
     * @param payload Object that is supposed to contain all fields for given type
     * @private
     */
    private _encodeData;
    /**
     * Applies a keccak256 hash to the result of _encodeData
     *
     * @param type Name of the type
     * @param data Object that is supposed to contain all fields for given type
     * @private
     */
    private _hashData;
    /**
     * Recursively finds all the dependencies of given type. Required to encode the type.
     *
     * @param type Name of the type
     * @param met Map that stores types already found in the recursive process
     * @private
     */
    private _getDependenciesOf;
    /**
     * Taking all types, getting all dependencies, putting main type first then all the rest
     * sorted. 100% Inspired by what was done in eth-sig-util
     *
     * @param type
     * @private
     */
    private _encodeType;
    /**
     * Applies a keccak256 hash to the result of _encodeType
     *
     * @param type Name of the type
     * @private
     */
    private _hashType;
    /**
     * Helper that verifies the types field on the provided payload
     *
     * @param payload Payload to verify
     * @private
     */
    private _verifyTypes;
    /**
     * Helper that verifies the domain field on the provided payload
     *
     * @param payload Payload to verify
     * @private
     */
    private _verifyDomain;
    /**
     * Helper that verifies the primaryType field on the provided payload
     *
     * @param payload Payload to verify
     * @private
     */
    private _verifyPrimaryType;
    /**
     * Helper that verifies that all required fields are present
     *
     * @param payload Payload to verify
     * @private
     */
    private _verifyMainPayloadField;
    /**
     * Interprets a `Buffer` as a signed integer and returns a `BN`. Assumes 256-bit numbers.
     *
     * @param num Signed integer value
     */
    private _fromSigned;
    /**
     * Converts a `BN` to an unsigned integer and returns it as a `Buffer`. Assumes 256-bit numbers.
     *
     * @param num
     */
    private _toUnsigned;
    /**
     * Pads provided string value to match provided length value.
     *
     * @param toPad Starting string to pad
     * @param length Target length
     * @private
     */
    private static _padWithZeroes;
    /********** PUBLIC INTERFACE ***********/
    /**
     * Sets all information related to the signatures that will be generated.
     *
     * @param domain Domain structure
     * @param primary_type Primary Type to use
     * @param types Arrays containing name and fields
     */
    constructor(domain: EIP712Domain, ...types: [string, EIP712Struct][]);
    /**
     * Throws if provided payload does not match current settings
     *
     * @param payload Payload to verify
     */
    verifyPayload(payload: EIP712Payload): void;
    /**
     * Encode the given payload
     *
     * @param payload Payload to encode
     * @param verify True if verifications should be made
     */
    encode(payload: EIP712Payload, verify?: boolean): string;
    /**
     * Sign the given payload
     *
     * @param privateKey Private key to use
     * @param payload Payload to sign
     * @param verify True if verifications should be made
     */
    sign(privateKey: string | ExternalSigner, payload: EIP712Payload, verify?: boolean): Promise<EIP712Signature>;
    /**
     * Verifies the given signature
     *
     * @param payload Payload used to generate the signature
     * @param signature Signature to verify
     * @param verify True if payload verifications should be made
     */
    verify(payload: EIP712Payload, signature: string, verify?: boolean): Promise<string>;
    /**
     * Helper that generates a complete payload, ready for signature (should work with web3, metamask etc)
     *
     * @param data Message field in the generated payload
     * @param primaryType Main type of given data
     */
    generatePayload(data: any, primaryType: string): EIP712Payload;
}

export { EIP712Domain, EIP712DomainType, EIP712Payload, EIP712Signature, EIP712Signer, EIP712Struct, EIP712StructField, ExternalSigner };
