const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { getBaseName, checkIPv6Enabled, groupByIPv4, P2P, STREAMING, IPV6 } = require('./app');

describe('getBaseName', () => {
  it('extracts base name before #', () => {
    assert.equal(getBaseName('US#42'), 'US');
  });

  it('returns full name when no # present', () => {
    assert.equal(getBaseName('US'), 'US');
  });

  it('handles multiple # characters by splitting on first', () => {
    assert.equal(getBaseName('CH-US#1#2'), 'CH-US');
  });

  it('returns empty string for name starting with #', () => {
    assert.equal(getBaseName('#42'), '');
  });

  it('handles empty string', () => {
    assert.equal(getBaseName(''), '');
  });
});

describe('checkIPv6Enabled', () => {
  it('returns true when domain has IPv6 addresses', () => {
    const domainResult = { domain: 'test.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: ['::1'] };
    assert.equal(checkIPv6Enabled(domainResult, []), true);
  });

  it('returns true when a server has IPv6 addresses', () => {
    const domainResult = { domain: 'test.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [] };
    const servers = [{ ipv6: ['::1'] }, { ipv6: [] }];
    assert.equal(checkIPv6Enabled(domainResult, servers), true);
  });

  it('returns false when neither domain nor servers have IPv6', () => {
    const domainResult = { domain: 'test.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [] };
    const servers = [{ ipv6: [] }];
    assert.equal(checkIPv6Enabled(domainResult, servers), false);
  });

  it('returns false with empty servers array and no domain IPv6', () => {
    const domainResult = { domain: 'test.protonvpn.net', ipv4: ['1.2.3.4'], ipv6: [] };
    assert.equal(checkIPv6Enabled(domainResult, []), false);
  });
});

describe('feature flag constants', () => {
  it('P2P equals 4', () => {
    assert.equal(P2P, 4);
  });

  it('STREAMING equals 8', () => {
    assert.equal(STREAMING, 8);
  });

  it('IPV6 equals 16', () => {
    assert.equal(IPV6, 16);
  });

  it('P2P flag detection via bitwise AND', () => {
    const features = 4;
    assert.equal((features & P2P) !== 0, true);
    assert.equal((features & STREAMING) !== 0, false);
  });

  it('STREAMING flag detection via bitwise AND', () => {
    const features = 8;
    assert.equal((features & STREAMING) !== 0, true);
    assert.equal((features & P2P) !== 0, false);
  });

  it('combined P2P+STREAMING flags detected independently', () => {
    const features = P2P | STREAMING;
    assert.equal((features & P2P) !== 0, true);
    assert.equal((features & STREAMING) !== 0, true);
    assert.equal((features & IPV6) !== 0, false);
  });

  it('no features set yields false for all flags', () => {
    const features = 0;
    assert.equal((features & P2P) !== 0, false);
    assert.equal((features & STREAMING) !== 0, false);
    assert.equal((features & IPV6) !== 0, false);
  });
});

describe('groupByIPv4', () => {
  function makeEntry(name, city, ipv4s, ipv6s, p2p, streaming, ipv6Enabled) {
    return {
      Name: name,
      Domain: { domain: name.toLowerCase().replace('#', '-') + '.protonvpn.net', ipv4: ipv4s, ipv6: ipv6s },
      City: city,
      ipv6Enabled,
      Servers: ipv4s.map((ip, i) => ({
        Domain: name.toLowerCase().replace('#', '-') + '.protonvpn.net',
        ipv4: [ip],
        ipv6: i === 0 ? ipv6s : [],
        X25519PublicKey: 'key' + i,
        EntryIP: ip,
        ExitIP: ip
      })),
      P2P: p2p,
      Streaming: streaming
    };
  }

  it('groups entries by IPv4 address', () => {
    const entries = [makeEntry('US#1', 'New York', ['1.2.3.4'], [], false, false, false)];
    const result = groupByIPv4(entries);
    assert.equal(result.length, 1);
    assert.equal(result[0].ipv4, '1.2.3.4');
  });

  it('deduplicates server names for same IPv4', () => {
    const entry1 = { ...makeEntry('US#1', 'New York', ['1.2.3.4'], [], false, false, false) };
    const entry2 = { ...makeEntry('US#2', 'New York', ['1.2.3.4'], [], false, false, false) };
    const result = groupByIPv4([entry1, entry2]);
    const ipEntry = result.find(r => r.ipv4 === '1.2.3.4');
    assert.ok(ipEntry);
    assert.deepEqual(ipEntry.servers, ['US#1', 'US#2']);
  });

  it('does not add duplicate server names', () => {
    const entry = makeEntry('US#1', 'New York', ['1.2.3.4', '1.2.3.4'], [], false, false, false);
    const result = groupByIPv4([entry]);
    const ipEntry = result.find(r => r.ipv4 === '1.2.3.4');
    assert.ok(ipEntry);
    assert.deepEqual(ipEntry.servers, ['US#1']);
  });

  it('picks first IPv6 address from server for grouped entry', () => {
    const entry = makeEntry('US#1', 'New York', ['1.2.3.4'], ['::1', '::2'], false, false, true);
    const result = groupByIPv4([entry]);
    assert.equal(result[0].ipv6, '::1');
  });

  it('sets ipv6 to null when server has no IPv6', () => {
    const entry = makeEntry('US#1', 'New York', ['1.2.3.4'], [], false, false, false);
    const result = groupByIPv4([entry]);
    assert.equal(result[0].ipv6, null);
  });

  it('preserves city, P2P, Streaming, ipv6Enabled from entry', () => {
    const entry = makeEntry('US#1', 'LA', ['5.6.7.8'], ['::1'], true, true, true);
    const result = groupByIPv4([entry]);
    assert.equal(result[0].city, 'LA');
    assert.equal(result[0].P2P, true);
    assert.equal(result[0].Streaming, true);
    assert.equal(result[0].ipv6Enabled, true);
  });

  it('handles entry with multiple servers on different IPv4s', () => {
    const entry = {
      Name: 'US#1',
      Domain: { domain: 'us-1.protonvpn.net', ipv4: [], ipv6: [] },
      City: 'NYC',
      ipv6Enabled: false,
      Servers: [
        { Domain: 's1.protonvpn.net', ipv4: ['10.0.0.1'], ipv6: [], X25519PublicKey: 'k1', EntryIP: '10.0.0.1', ExitIP: '10.0.0.1' },
        { Domain: 's2.protonvpn.net', ipv4: ['10.0.0.2'], ipv6: [], X25519PublicKey: 'k2', EntryIP: '10.0.0.2', ExitIP: '10.0.0.2' }
      ],
      P2P: false,
      Streaming: false
    };
    const result = groupByIPv4([entry]);
    assert.equal(result.length, 2);
    assert.equal(result[0].ipv4, '10.0.0.1');
    assert.equal(result[1].ipv4, '10.0.0.2');
  });

  it('returns empty array for empty input', () => {
    const result = groupByIPv4([]);
    assert.deepEqual(result, []);
  });
});
