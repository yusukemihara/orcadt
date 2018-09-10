#!/usr/bin/ruby1.9.1
# coding : utf-8

require "openssl"
require "open-uri"
require "optparse"
require "uri"

#Orca Data Transfer
module OrcaDT
  class Verifier

    VALID_SIGNER_LIST = [
      "/C=JP/ST=Tokyo/L=Bunkyo/O=ORCA Management Organization Co., Ltd./OU=ORCA Project/CN=ORCA Management Organization Co., Ltd./emailAddress=delegate@orcamo.co.jp",
      "/C=JP/L=Tokyo/O=MED/OU=ORCA Project/CN=JMA standard receipt software team"
    ]

    def Verifier.selfsigned?(cert)
      ski = nil
      aki = nil
      cert.extensions.each do |e|
        case e.oid
        when "subjectKeyIdentifier"
          ski = e.value
        when "authorityKeyIdentifier"
          aki = e.value
        end
      end
      return true if ski and aki and ski == aki
      false
    end

    def Verifier.verify(url, opts)
      # open
      smime = nil
      begin
        smime = File.read(url)
      rescue Errno::ENOENT
        OpenURI.open_uri(url,
          :http_basic_authentication => [opts["user"], opts["password"]]
        ) {|sio| smime = sio.read }
      end 

      # NOCHAINとしつつ下でstoreに追加している、NOCHAINをはずすとなぜかverify errorになるため
      flag = OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOCHAIN
      p7 = OpenSSL::PKCS7.read_smime(smime)

      data = nil
      if opts["do_verify"]
        #verify
        store = OpenSSL::X509::Store.new
        store.set_default_paths
        store.add_file(opts["cacert"])
        p7.certificates.each do |c|
          begin
            # ルート証明書以外をstoreに追加
            store.add_cert(c) if not selfsigned?(c)
          rescue OpenSSL::X509::StoreError
          end
        end
        unless p7.verify(p7.certificates, store, p7.data, flag);
          raise "pkcs7 verify error #{p7.error_string}"
        end

        #subjectのチェック
        subject = p7.certificates[0].subject.to_s
        unless VALID_SIGNER_LIST.include?(subject)
          raise "unknown signer #{subject}"
        end

        #check crl
        if opts["crl"]
          crl = OpenSSL::X509::CRL.new(File.read(opts["crl"]))
          cacert = OpenSSL::X509::Certificate.new(File.read(opts["cacert"]))
          signercert = p7.certificates[0]
          unless crl.verify(cacert.public_key) 
            raise "crl verify error #{opts["crl"]}"
          end
          if crl.revoked.find{|rc| rc.serial == signercert.serial}
            raise "signer cert was revoced #{signercert.subject}"
          end
        end
        data = p7.data
        puts "[SUCCESS] verify #{url}"
      else
        data = OrcaDT.extract_pkcs7_data(p7)
      end

      #save file
      basename = File.basename(URI.parse(url).path).to_s.sub(/\.p7m$/,"")
      path = File.join(opts["dir"], basename)
      File.open(path, "w"){ |io|
        io.write(data)
      }
      puts "[SUCCESS] store #{path}"
    end
  end

  module_function

  def extract_pkcs7_data(pkcs7)
=begin
  from RFC 2630
      ContentInfo ::= SEQUENCE {
        contentType ContentType,
        content [0] EXPLICIT ANY DEFINED BY contentType 
          # => OpenSSL::ASN1::ASN1Data => SignedData : OpenSSL::Sequence
      }

      ContentType ::= OBJECT IDENTIFIER

      SignedData ::= SEQUENCE {
        version CMSVersion,                                    
          # => OpenSSL::ASN1::Integer
        digestAlgorithms DigestAlgorithmIdentifiers,           
          # => OpenSSL::ASN1::Set
        encapContentInfo EncapsulatedContentInfo,              
          # => OpenSSL::ASN1::Sequence
        certificates [0] IMPLICIT CertificateSet OPTIONAL,     
          # => ?
        crls [1] IMPLICIT CertificateRevocationLists OPTIONAL, 
          # => ?
        signerInfos SignerInfos                                
          # => OpenSSL::ASN1::Set
      }

      DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

      SignerInfos ::= SET OF SignerInfo

      EncapsulatedContentInfo ::= SEQUENCE {
        eContentType ContentType,                     
          #=> OpenSSL::ASN1::ObjectId
        eContent [0] EXPLICIT OCTET STRING OPTIONAL   
          #=> OpenSSL::ASN1::ASN1Data => OpenSSL::ASN1::OctetString
      }

      ContentType ::= OBJECT IDENTIFIER
=end
    signed_data = OpenSSL::ASN1.decode(pkcs7).value[1].value[0]
    encap_content_info = signed_data.value[2] if signed_data
    econtent = encap_content_info.value[1] if encap_content_info
    data = econtent.value[0].value if econtent
    return data
  end

end

def parse_option(argv0, argv)
  option_spec = [
   ["--dir=VAL"   , "output directory"    , "dir"],
   ["--cacert=VAL", "ca certificate path" , "cacert"],
   ["--crl=VAL"   , "crl certificate path", "crl"],
   ["--user=VAL"   , "basic authentication user", "user"],
   ["--password=VAL"   , "basic authentication password", "password"],
  ]
  options = {}
  options["do_verify"] = true
  parser = OptionParser.new{|opts|
    opts.banner = "Usage: #{File.basename(argv0)} [options]\n"
    opts.on_head("options:")
    option_spec.each{|long, desc, key|
      opts.on("", long, desc){|arg|
        options[key] = arg
      }
    }
    opts.on("", "--no-verify", "don't verify") {
      options["do_verify"] = false
    }
    opts.on_tail('--help', 'show this message'){
      raise "help specified"
    }
  }
  begin
    parser.parse!(argv)
  rescue RuntimeError => ex
    puts parser;
    exit 1;
  end
  return options
end

if $0 == __FILE__
  opts = parse_option($0, ARGV)
  unless opts["dir"]
    puts "specify --dir"
    exit 1
  end
  begin
    ARGV.each{|url|
      OrcaDT::Verifier.verify(url, opts)
    }
  rescue Exception => ex
    puts "[ERROR] #{ex.message}"
    puts ex.backtrace
    exit 1
  end
  exit 0
end
