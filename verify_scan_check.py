from scanner_utils import analyze_uploaded_file

r1 = analyze_uploaded_file('report.pdf', b'%PDF-1.4', 'application/pdf')
r2 = analyze_uploaded_file('six.bin', b'0' * (6 * 1024 * 1024), 'application/octet-stream')
r3 = analyze_uploaded_file('fourteen.bin', b'0' * (14 * 1024 * 1024), 'application/octet-stream')
r4 = analyze_uploaded_file('big.bin', b'0' * (15 * 1024 * 1024 + 1), 'application/octet-stream')
r5 = analyze_uploaded_file('unsupported.xyz', b'hello', 'application/octet-stream')

print('r1', r1.get('success'), r1.get('status'))
print('r2', r2.get('success'), r2.get('status'))
print('r3', r3.get('success'), r3.get('status'))
print('r4', r4.get('success'), r4.get('message'))
print('r5', r5.get('success'), r5.get('status'))

assert r1['success']
assert r2['success']
assert r3['success']
assert not r4['success']
assert r5['success'] and r5['status'] == 'Unsupported Format'
