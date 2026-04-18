// Quick functional test of OPAQUE protocol
import { generateOprfKey, oprfClientBlind, oprfServerEvaluate, oprfClientUnblind } from './src/oprf';

async function test() {
  console.log('Testing OPAQUE protocol...\n');

  // Setup
  const password = 'testpass123';
  const oprfKey = await generateOprfKey();
  console.log('✓ Generated OPRF key pair');

  // OPRF flow
  const { blind, blindingFactor } = await oprfClientBlind(password);
  console.log('✓ Client blind: password hidden with random factor');

  const evaluated = await oprfServerEvaluate(oprfKey.oprfPrivate, blind);
  console.log('✓ Server evaluate: computed with secret key');

  const rwd = await oprfClientUnblind(password, evaluated, blindingFactor);
  console.log('✓ Client unblind: derived key without knowing server secret\n');

  // Verify determinism
  const { blind: blind2, blindingFactor: bf2 } = await oprfClientBlind(password);
  const evaluated2 = await oprfServerEvaluate(oprfKey.oprfPrivate, blind2);
  const rwd2 = await oprfClientUnblind(password, evaluated2, bf2);

  if (Buffer.from(rwd).toString('hex') === Buffer.from(rwd2).toString('hex')) {
    console.log('✓ OPRF determinism verified: same password → same rwd');
  } else {
    console.log('✗ OPRF determinism FAILED');
    process.exit(1);
  }

  // Verify different password gives different rwd
  const { blind: blind3, blindingFactor: bf3 } = await oprfClientBlind('different');
  const evaluated3 = await oprfServerEvaluate(oprfKey.oprfPrivate, blind3);
  const rwd3 = await oprfClientUnblind('different', evaluated3, bf3);

  if (Buffer.from(rwd).toString('hex') !== Buffer.from(rwd3).toString('hex')) {
    console.log('✓ OPRF password sensitivity verified: different password → different rwd\n');
  } else {
    console.log('✗ OPRF password sensitivity FAILED');
    process.exit(1);
  }

  console.log('All functional tests passed!');
  process.exit(0);
}

test().catch(e => {
  console.error('Test failed:', e);
  process.exit(1);
});
