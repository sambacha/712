import {
  EIP712DomainType,
  EIP712Payload,
  EIP712Signer,
  EIP712Signature,
} from './EIP712Signer';
import * as ESU from 'eth-sig-util';
import { expect } from 'chai';
import { utils, Wallet } from 'ethers';
import BN from 'bn.js';

const primaryType = 'Mail';

const UselessType = [
  {
    name: 'useless',
    type: 'bool',
  },
];

const Person = [
  {
    name: 'name',
    type: 'string',
  },
  {
    name: 'wallet',
    type: 'address',
  },
  {
    name: 'usernames',
    type: 'bytes32[]',
  },
  {
    name: 'points',
    type: 'bytes',
  },
  {
    name: 'useless_one',
    type: 'UselessType',
  },
  {
    name: 'useless_two',
    type: 'UselessType',
  },
  {
    name: 'integer_value',
    type: 'uint256',
  },
];

const Mail = [
  {
    name: 'from',
    type: 'Person',
  },
  {
    name: 'to',
    type: 'Person',
  },
  {
    name: 'contents',
    type: 'string',
  },
];

const types = {
  Mail,
  Person,
  UselessType,
};

const domain = {
  name: 'Ether Mail',
  version: '1',
  chainId: 1,
  verifyingContract: '0xe4937b3fead67f09f5f15b0a1991a588f7be54ca',
};

const payload = {
  from: {
    name: 'lol',
    wallet: '0xe4937b3fead67f09f5f15b0a1991a588f7be54ca',
    usernames: [],
    points: '0x1243',
    useless_one: {
      useless: true,
    },
    useless_two: null,
    integer_value: new BN(12),
  },
  to: {
    name: 'lele',
    wallet: '0xc7449fedabef2cf2749b7c83448fba9bc8dc273d',
    usernames: [
      '0x0000000000000000000000000000000000000000000000000000000000000001',
      '0x1000000000000000000000000000000000000000000000000000000000000000',
    ],
    points: '0xabbc',
    useless_one: {
      useless: true,
    },
    useless_two: {
      useless: false,
    },
    integer_value: 12,
  },
  contents: 'Hello lele',
};

class UnbuildableEtherMail extends EIP712Signer {
  constructor() {
    super(
      domain,
      ['Mail', Mail],
      ['Person', Person],
      ['EIP712Domain', EIP712DomainType],
    );
  }
}

// tslint:disable-next-line:max-classes-per-file
class EtherMail extends EIP712Signer {
  constructor() {
    super(
      domain,
      ['Mail', Mail],
      ['Person', Person],
      ['UselessType', UselessType],
    );
  }
}

describe('e712 tests', (): void => {
  it('encodeType', (): void => {
    const em = new EtherMail();

    expect((ESU as any).TypedDataUtils.encodeType('Mail', types)).to.equal(
      (em as any)._encodeType('Mail'),
    );

    expect((ESU as any).TypedDataUtils.encodeType('Person', types)).to.equal(
      (em as any)._encodeType('Person'),
    );
  });

  it('hashType', (): void => {
    const em = new EtherMail();

    expect(
      '0x' +
        (ESU as any).TypedDataUtils.hashType('Mail', types).toString('hex'),
    ).to.equal((em as any)._hashType('Mail'));

    expect(
      '0x' +
        (ESU as any).TypedDataUtils.hashType('Person', types).toString('hex'),
    ).to.equal((em as any)._hashType('Person'));
  });

  it('encodeData', (): void => {
    const em = new EtherMail();

    expect(
      '0x' +
        (ESU as any).TypedDataUtils.encodeData('Mail', payload, types).toString(
          'hex',
        ),
    ).to.equal((em as any)._encodeData('Mail', payload));
  });

  it('EIP712Signer - hashData', (): void => {
    const em = new EtherMail();

    expect(
      '0x' +
        (ESU as any).TypedDataUtils.hashStruct('Mail', payload, types).toString(
          'hex',
        ),
    ).to.equal((em as any)._hashData('Mail', payload));
  });

  it('encode', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    expect(
      '0x' +
        (ESU as any).TypedDataUtils.sign(formatted_payload).toString('hex'),
    ).to.equal(utils.keccak256(em.encode(formatted_payload)));
  });

  it('encode EIP712Domain', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType: 'EIP712Domain',
      types: {
        EIP712Domain: EIP712DomainType,
      },
    };

    expect(
      '0x' +
        (ESU as any).TypedDataUtils.sign(formatted_payload).toString('hex'),
    ).to.equal(utils.keccak256(em.encode(formatted_payload, true)));
  });

  it('encode and verify', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    expect(
      '0x' +
        (ESU as any).TypedDataUtils.sign(formatted_payload).toString('hex'),
    ).to.equal(utils.keccak256(em.encode(formatted_payload, true)));
  });

  it('verifyPayload', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    // Nothing happens if everything is ok
    em.verifyPayload(formatted_payload);
  });

  it('verifyPayload with missing field', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with missing field in domain', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 1,
      },
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with errored name field', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      demain: domain,
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with errored type field - good number but one differs', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        MailPerson: [],
        Person,
        UselessType,
        EIP712Domain: EIP712DomainType,
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with errored type field - good number but hash mismatching fields', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        Mail,
        Person,
        UselessType: [
          {
            name: 'uselesss',
            type: 'bool',
          },
        ],
        EIP712Domain: EIP712DomainType,
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with errored type count', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        Mail,
        Person,
        UselessType,
        EIP712Domain: EIP712DomainType,
        MailPerson: [],
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with errored EIP712Domain type definition - mismatch in field types', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        Mail,
        Person,
        UselessType,
        EIP712Domain: [
          ...EIP712DomainType,
          {
            name: 'name',
            type: 'uint256',
          },
        ],
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with errored EIP712Domain type definition - extra field', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        Mail,
        Person,
        EIP712Domain: [
          ...EIP712DomainType,
          {
            name: 'extra',
            type: 'uint256',
          },
        ],
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with missing type', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types,
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with errored message - missing field', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: {
        from: payload.from,
        to: payload.to,
      },
      primaryType,
      types: {
        ...types,
        EIP712Domain: [...EIP712DomainType],
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with errored message - field name error', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: {
        from: payload.from,
        to: payload.to,
        content: payload.contents,
      },
      primaryType,
      types: {
        ...types,
        EIP712Domain: [...EIP712DomainType],
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('verifyPayload with EIP712Domain as primaryType', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType: 'EIP712Domain',
      types: {
        EIP712Domain: [...EIP712DomainType],
      },
    };

    em.verifyPayload(formatted_payload as any);
  });

  it('verifyPayload and exchange BN and numbers', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: {
        ...payload,
        from: {
          ...payload.from,
          integer_value: 12,
        },
        to: {
          ...payload.to,
          integer_value: new BN(12),
        },
      },
      primaryType: 'EIP712Domain',
      types: {
        EIP712Domain: [...EIP712DomainType],
      },
    };

    em.verifyPayload(formatted_payload as any);
  });

  it('verifyPayload with Person as primaryType', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType: 'Person',
      types: {
        ...types,
        EIP712Domain: [...EIP712DomainType],
      },
    };

    expect((): void => {
      em.verifyPayload(formatted_payload as any);
    }).to.throw();
  });

  it('encode with missing field', (): void => {
    const em = new EtherMail();

    const formatted_payload = {
      message: payload,
      primaryType: 'EIP712Domain',
      types: {
        ...types,
        EIP712Domain: [...EIP712DomainType],
      },
    };

    expect((): void => {
      em.encode(formatted_payload as any);
    }).to.throw();
  });

  it('type addition collision', (): void => {
    expect((): void => {
      const em = new UnbuildableEtherMail();
    }).to.throw();
  });

  it('sign and verify with eth-sig-util', async (): Promise<void> => {
    const ew = Wallet.createRandom();
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    const signature = await em.sign(ew.privateKey, formatted_payload);

    expect(
      ESU.recoverTypedSignature_v4({
        data: formatted_payload,
        sig: signature.hex,
      }).toLowerCase(),
    ).to.equal(ew.address.toLowerCase());
  });

  it('sign and verify payload', async (): Promise<void> => {
    const ew = Wallet.createRandom();
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    const signature = await em.sign(ew.privateKey, formatted_payload, true);

    expect(
      ESU.recoverTypedSignature_v4({
        data: formatted_payload,
        sig: signature.hex,
      }).toLowerCase(),
    ).to.equal(ew.address.toLowerCase());
  });

  it('sign with custom external signer and verify payload', async (): Promise<void> => {
    const ew = Wallet.createRandom();
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    const _padWithZeroes = (toPad: string, length: number): string => {
      let myString = '' + toPad;
      while (myString.length < length) {
        myString = '0' + myString;
      }
      return myString;
    };

    const _fromSigned = (num: string): BN => {
      return new BN(Buffer.from(num.slice(2), 'hex')).fromTwos(256);
    };

    const _toUnsigned = (num: BN): Buffer => {
      return Buffer.from(num.toTwos(256).toArray());
    };

    const signer = async (encodedPayload: string): Promise<EIP712Signature> => {
      const sk = new utils.SigningKey(ew.privateKey);

      const hashedPayload = utils.keccak256(
        Buffer.from(encodedPayload.slice(2), 'hex'),
      );
      const signature = sk.signDigest(
        Buffer.from(hashedPayload.slice(2), 'hex'),
      );

      const rSig = _fromSigned(signature.r);
      const sSig = _fromSigned(signature.s);
      const vSig = signature.v;
      const rStr = _padWithZeroes(_toUnsigned(rSig).toString('hex'), 64);
      const sStr = _padWithZeroes(_toUnsigned(sSig).toString('hex'), 64);
      const vStr = vSig.toString(16);

      return {
        hex: `0x${rStr}${sStr}${vStr}`,
        v: vSig,
        r: rStr,
        s: sStr,
      };
    };

    const signature = await em.sign(signer, formatted_payload, true);

    expect(
      ESU.recoverTypedSignature_v4({
        data: formatted_payload,
        sig: signature.hex,
      }).toLowerCase(),
    ).to.equal(ew.address.toLowerCase());
  });

  it('sign with eth-sig-util and verify with own verifier', async (): Promise<void> => {
    const ew = Wallet.createRandom();
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    const signature = ESU.signTypedData_v4(
      Buffer.from(ew.privateKey.slice(2), 'hex'),
      {
        data: formatted_payload,
      },
    );

    expect(
      (await em.verify(formatted_payload, signature, true)).toLowerCase(),
    ).to.equal(ew.address.toLowerCase());
  });

  it('sign and verify with own signer & verifier', async (): Promise<void> => {
    const ew = Wallet.createRandom();
    const em = new EtherMail();

    const formatted_payload = {
      domain,
      message: payload,
      primaryType,
      types: {
        ...types,
        EIP712Domain: EIP712DomainType,
      },
    };

    const signature = await em.sign(ew.privateKey, formatted_payload, true);
    expect(
      (await em.verify(formatted_payload, signature.hex)).toLowerCase(),
    ).to.equal(ew.address.toLowerCase());
  });

  it('generate payload, sign and verify with own signer & verifier', async (): Promise<void> => {
    const ew = Wallet.createRandom();
    const em = new EtherMail();

    const formatted_payload = em.generatePayload(payload, 'Mail');

    const signature = await em.sign(ew.privateKey, formatted_payload, true);
    expect(
      (await em.verify(formatted_payload, signature.hex)).toLowerCase(),
    ).to.equal(ew.address.toLowerCase());
  });

  it('pads and verifies', async (): Promise<void> => {
    const em = new EtherMail();
    const str = 'abc';

    const padded = (EIP712Signer as any)._padWithZeroes(str, 62);

    expect(padded).to.equal(
      '00000000000000000000000000000000000000000000000000000000000abc',
    );
  });

  //Metamask does not support null values & arrays
  it('test metamask result', async (): Promise<void> => {
    const signature =
      '0x6855e9255fb16a18c2344ecb25e1a0ca05fdd5d2c8e985c066ea1b55ee9129dc6792ca716b617dc9311321ce6350c5237356021ea88afec54ccc98458089704c1b';
    const address = '0x14Fd1C6E490208216Fc8CeA209C990Eb484d8477';

    const payload = {
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 1,
        verifyingContract: '0xe4937b3fead67f09f5f15b0a1991a588f7be54ca',
      },
      message: {
        from: {
          name: 'lol',
          wallet: '0xe4937b3fead67f09f5f15b0a1991a588f7be54ca',
          points: '0x1243',
        },
        to: {
          name: 'lele',
          wallet: '0xc7449fedabef2cf2749b7c83448fba9bc8dc273d',
          points: '0xabbc',
        },
        contents: 'Hello lele',
      },
      primaryType: 'Mail',
      types: {
        Mail: [
          {
            name: 'from',
            type: 'Person',
          },
          {
            name: 'to',
            type: 'Person',
          },
          {
            name: 'contents',
            type: 'string',
          },
        ],
        Person: [
          {
            name: 'name',
            type: 'string',
          },
          {
            name: 'wallet',
            type: 'address',
          },
          {
            name: 'points',
            type: 'bytes',
          },
        ],
        UselessType: [
          {
            name: 'useless',
            type: 'bool',
          },
        ],
        EIP712Domain: [
          {
            name: 'name',
            type: 'string',
          },
          {
            name: 'version',
            type: 'string',
          },
          {
            name: 'chainId',
            type: 'uint256',
          },
          {
            name: 'verifyingContract',
            type: 'address',
          },
        ],
      },
    };

    const em = new EIP712Signer(
      payload.domain,
      ['Mail', payload.types.Mail],
      ['Person', payload.types.Person],
    );

    expect((await em.verify(payload, signature)).toLowerCase()).to.equal(
      address.toLowerCase(),
    );
  });

  it('personal information use case', async (): Promise<void> => {
    //
    // Setup
    //

    const User = [
      {
        name: 'firstName',
        type: 'string',
      },
      {
        name: 'lastName',
        type: 'string',
      },
      {
        name: 'age',
        type: 'uint256',
      },
    ];

    const domain = {
      name: 'User Infos',
      version: '1',
      chainId: 1,
      verifyingContract: '0xe4937b3fead67f09f5f15b0a1991a588f7be54ca',
    };

    const primaryType = 'User';

    // tslint:disable-next-line:max-classes-per-file
    class UserInfos extends EIP712Signer {
      private firstName: string = null;
      private lastName: string = null;
      private age: number = null;

      constructor() {
        super(domain, ['User', User]);
      }

      setUserInfos(firstName: string, lastName: string, age: number): void {
        if (!firstName || !lastName || age <= 0) {
          throw new Error('Invalid User Information');
        }

        this.firstName = firstName;
        this.lastName = lastName;
        this.age = age;
      }

      getSignature(privateKey: string): Promise<EIP712Signature> {
        const payload = this.getPayload();

        return this.sign(privateKey, payload);
      }

      async getSignerAddress(
        firstName: string,
        lastName: string,
        age: number,
        signature: string,
      ): Promise<string> {
        if (!firstName || !lastName || age <= 0) {
          throw new Error('Invalid User Information');
        }

        const message_paylaod = {
          firstName: this.firstName,
          lastName: this.lastName,
          age: this.age,
        };

        const original_payload = this.generatePayload(message_paylaod, 'User');

        return this.verify(original_payload, signature);
      }

      getPayload(): EIP712Payload {
        const message_paylaod = {
          firstName: this.firstName,
          lastName: this.lastName,
          age: this.age,
        };

        return this.generatePayload(message_paylaod, 'User');
      }
    }

    //
    // Usage - User end
    //

    const user_infos = new UserInfos();

    user_infos.setUserInfos('John', 'Doe', 22);

    // Generate the signature in place

    const my_user_wallet = Wallet.createRandom();

    const signature = await user_infos.getSignature(my_user_wallet.privateKey);

    console.log('Signed by ', my_user_wallet.address);

    // If users uses a web3 browser able to sign the payloads itself, provide the following data as argument

    const ready_to_sign_with_third_party_wallet_provider =
      user_infos.getPayload();

    //
    // Usage - Verification End
    //

    // Pretend this has been provided in some way to the verification end
    const firstName = 'John';
    const lastName = 'Doe';
    const age = 22;

    const signer = await user_infos.getSignerAddress(
      firstName,
      lastName,
      age,
      signature.hex,
    );

    console.log('Signature signed by ', signer);
  });
});
