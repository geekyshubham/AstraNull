import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

// Independent wire expectations only: no payload producer imports and no send API.
// Every admitted bounded service request is checked against peer-received bytes.
export function assertDeliveredReflectorRequest(receipt) {
  const profile = receipt.signed_profile.payload_profile;
  const row = receipt.actual_wire.find((entry) => entry.payload_profile === profile && ['udp', 'reflection_tcp'].includes(entry.transport));
  assert.ok(row, `${profile}: peer-received request bytes required`);
  const bytes = Buffer.from(row.request_hex, 'hex');
  assert.ok(bytes.length <= 512);
  const id = createHash('sha256').update(receipt.signed_job.nonce_hash).digest();
  const hex = (value) => Buffer.from(value, 'hex');
  const fixed = {
    chargen_trigger: '', ipmi_rmcp_ping: '0600ff06000011be80000000',
    mssql_resolution_request: '02', jenkins_discovery: '00', natpmp_external_address: '0000',
    cldap_root_dse: '3025020101632004000a01000a0100020101020101010100870b6f626a656374436c6173733000',
  };
  if (Object.hasOwn(fixed, profile)) assert.deepEqual(bytes, hex(fixed[profile]));
  else if (profile === 'ssdp_msearch') assert.equal(bytes.toString('ascii'), 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n');
  else if (profile === 'tftp_read_request') assert.deepEqual(bytes, Buffer.concat([hex('0001'), Buffer.from('astranull-nonexistent\0octet\0')]));
  else if (profile === 'snmp_v2c_get_sysdescr') assert.deepEqual(bytes, Buffer.concat([hex('302902010104067075626c6963a01c0204'), id.subarray(0, 4), hex('020100020100300e300c06082b060102010101000500')]));
  else if (profile === 'memcached_udp_stats') assert.deepEqual(bytes, Buffer.concat([id.subarray(0, 2), hex('000000010000'), Buffer.from('stats\r\n')]));
  else if (profile === 'ntp_mode6_readvar') assert.deepEqual(bytes, Buffer.concat([hex('2602'), id.subarray(0, 2), Buffer.alloc(8)]));
  else if (profile === 'coap_get_wellknown') assert.deepEqual(bytes, Buffer.concat([hex('4001'), id.subarray(0, 2), hex('bb'), Buffer.from('.well-known'), hex('04'), Buffer.from('core')]));
  else if (profile === 'openvpn_reset') assert.deepEqual(bytes, Buffer.concat([hex('38'), id.subarray(0, 8), hex('0000000001')]));
  else if (profile === 'portmap_dump') assert.deepEqual(bytes, Buffer.concat([hex('80000028'), id.subarray(0, 4), hex('0000000000000002000186a00000000200000004'), Buffer.alloc(16)]));
  else if (profile === 'tp240_status_request') assert.deepEqual(bytes, Buffer.concat([Buffer.alloc(4), id.subarray(0, 2)]));
  else if (profile === 'stun_binding_request') {
    assert.equal(bytes.length, 20);
    assert.deepEqual(bytes.subarray(0, 8), hex('000100002112a442'));
    assert.equal(bytes.subarray(8).length, 12, 'existing random transaction identifier is preserved');
  } else if (profile === 'mdns_ptr_query') {
    assert.deepEqual(bytes, hex('000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001'));
  } else if (profile === 'ws_discovery_probe') {
    assert.equal(bytes.toString('utf8'), '<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><e:Header><w:MessageID>urn:uuid:' + id.subarray(0, 16).toString('hex') + '</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe/></e:Body></e:Envelope>');
  } else if (profile === 'slp_srvrqst') {
    assert.deepEqual(bytes.subarray(0, 10), hex('02010000360000000000'));
    assert.deepEqual(bytes.subarray(10, 12), id.subarray(0, 2));
    assert.deepEqual(bytes.subarray(12), Buffer.concat([hex('0002'), Buffer.from('en'), hex('00000015'), Buffer.from('service:service-agent'), hex('0007'), Buffer.from('DEFAULT'), hex('00000000')]));
  } else if (profile === 'l2tp_sccrq') {
    assert.deepEqual(bytes, Buffer.concat([hex('c802003d000000000000000080080000000000018008000000020100800f00000007'), Buffer.from('astranull'), hex('800a0000000300000001800800000009'), id.subarray(0, 2)]));
  } else throw new Error(`Independent reflector wire assertion missing: ${profile}`);
  return `${profile}: exact peer payload contract`;
}
