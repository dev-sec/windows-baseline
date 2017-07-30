# encoding: utf-8

windows_certificates_nogov = attribute('windows_certificates_nogov', default: true, description: 'Ensure no certificates from a governmental entity')
## from Windows Participants: https://gallery.technet.microsoft.com/Trusted-Root-Certificate-123665ca
windows_certificates_nogov_list = %w(
      'ACCVRAIZ1',
      'AC RAIZ FNMT-RCM',
      'AC1 RAIZ MTIN',
      'Australian Defence Organisation (ADO) Certificate Authority 02',
      'Australian Defence Public Root CA',
      'Autoridad Certificadora Raíz Nacional de Uruguay',
      'Autoridad de Certificacion de la Abogacia',
      'Autoridad de Certificacion Firmaprofesional CIF A62634068',
      'Autoridad de Certificacion Raiz de la Republica Bolivariana de Venezuela',
      'Autoridad de Certificacion Raiz de la Republica Bolivariana de Venezuela 1',
      'Autoridade Certificadora da Raiz Brasileira v1 - ICP-Brasil',
      'Autoridade Certificadora Raiz Brasileira v2',
      'CCA India 2014',
      'CCA India 2015',
      'Certinomis - Autorité Racine',
      'Certinomis - Root CA',
      'Common Policy',
      'Correo Uruguayo - Root CA',
      'DIRECCION GENERAL DE LA POLICIA',
      'E-ME SSI (RCA)',
      'ECRaizEstado',
      'Fabrica Nacional de Moneda y Timbre',
      'Federal Government Common Policy',
      'Fotanúsítványkiadó - Kormányzati Hitelesítés Szolgáltató',
      'Government of Netherlands G3',
      'Government of Sweden (Försäkringskassan)',
      'Government Root Certification Authority - Taiwan',
      'GPKI ApplicationCA2 Root',
      'GPKIRootCA1',
      'KISA RootCA 1',
      'Hongkong Post Root CA 1',
      'Macao Post eSign Trust',
      'Posta CA Root',
      'POSTarCA',
      'PostSignum Root QCA 2',
      'Saudi National Root CA',
      'SAPO Class 2 Root CA',
      'SAPO Class 3 Root CA',
      'SAPO Class 4 Root CA',
      'Secrétariat Général de la Défense Nationale',
      'SI-TRUST Root',
      'Staat der Nederlanden EV Root CA',
      'Staat der Nederlanden Root CA - G2',
      'Swedish Government Root Authority v1',
      'Swedish Government Root Authority v3',
      'Swiss Government Root CA I',
      'Swiss Government Root CA II',
      'Swiss Government Root III',
      'Thailand National Root Certification Authority - G1',
      'TÜBITAK Kamu SM',
      'TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1',
      'Tunisian Root Certificate Authority - TunRootCA2',
      'TW Government Root Certification Authority',
      'TW Government Root Certification Authority 2',
      'VRK Gov. Root CA'
      'VAS Latvijas Pasts SSI(RCA)',
      'VI Registru Centras',
    )

title 'Windows Certificates store'

control 'certificates-100' do
  impact 1.0
  title 'Verify the content of Windows certificate store'
  ref url: 'https://support.microsoft.com/en-us/help/293781/trusted-root-certificates-that-are-required-by-windows-server-2008-r2,-by-windows-7,-by-windows-server-2008,-by-windows-vista,-by-windows-server-2003,-by-windows-xp,-and-by-windows-2000'
  describe powershell('dir cert:\ -rec') do
    # necessary and trusted root certificates
    its('stdout') { should match 'Microsoft Root Authority' }
    # its('stdout') { should match '00c1008b3c3c8811d13ef663ecdf40' }
    its('stdout') { should match 'Thawte Timestamping CA' }
    its('stdout') { should match 'Microsoft Root Certificate Authority' }
    #its('stdout') { should match '79ad16a14aa0a5ad4c7358f407132e65' }
    # (few) Known bad certificates
    its('stdout') { should_not match 'Diginotar' }
    its('stdout') { should_not match 'Superfish' }
    # https://sslbl.abuse.ch/
    its('stdout') { should_not match 'a9240e124ab94f16744d54c250f2df461ddc392b' }
  end
end

if windows_certificates_nogov
  title 'Windows governmental certificates'

  control 'certificates-200' do
    impact 1.0
    title 'Ensure no governmental certificate authorities in store unless approved'
    describe powershell('dir cert:\ -rec') do
      windows_certificates_nogov_list.each do |cert|
        its('stdout') { should_not match cert.to_s }
      end
    end
  end
end
