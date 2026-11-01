require 'json'
require 'yaml'
require 'digest'
require 'zlib'
require 'rubygems/package'
require 'base64'
archive='.artifacts/tools/crs-v4.25.1.tar.gz'
expected='0539e66e7627fe71c160a644d8fb7ab6e450d53c9de208be5f95a35c70e1a154'
raise 'CRS archive digest mismatch' unless Digest::SHA256.file(archive).hexdigest==expected
# Preserve binary test input without making JSON recode or discard its bytes.
def json_value(value)
 case value
 when Hash
  value.map {|key,item| [key,json_value(item)]}.to_h
 when Array
  value.map {|item| json_value(item)}
 when String
  text=value.dup.force_encoding('UTF-8')
  text.valid_encoding? ? text : {'selfguardBytesBase64'=>Base64.strict_encode64(value)}
 else value
 end
end
files=[]
errors=[]
Zlib::GzipReader.open(archive) do |gzip|
 Gem::Package::TarReader.new(gzip) do |tar|
  tar.each do |entry|
   next unless entry.file? && entry.full_name.match?(/\/tests\/regression\/tests\/.*\.yaml$/)
   raise 'oversized corpus file' if entry.header.size>4*1024*1024
   source=entry.read
   begin
    data=YAML.safe_load(source)
    raise 'unexpected corpus document shape' unless data.nil? || data.is_a?(Hash)
    files << {'path'=>entry.full_name.split('/').drop(1).join('/'),'sha256'=>Digest::SHA256.hexdigest(source),'document'=>json_value(data)}
   rescue StandardError=>error
    errors << {'path'=>entry.full_name,'error'=>error.class.name+': '+error.message}
   end
  end
 end
end
result={'archiveSha256'=>expected,'files'=>files,'errors'=>errors}
File.write('.artifacts/results/expansion/crs-full-corpus.json',JSON.pretty_generate(result)+"\n")
puts JSON.generate({'files'=>files.length,'tests'=>files.sum {|file| (file['document'].is_a?(Hash) ? file['document']['tests']||[] : []).length},'preparationErrors'=>errors.length})
exit(errors.empty? ? 0 : 1)
