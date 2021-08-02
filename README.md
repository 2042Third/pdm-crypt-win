<h1>pdm cryptography core module for windows</h1>
<p>
This a commandl line encryption tool for windows, for linux or macOS version please visit my other repository, 
  <a href="https://github.com/2042Third/pdm-crypt-module" target="_blank">pdm-crypt-module</a>.
</p>
<h2>CURRENT STATUS:</h2>
enabled sha3 checking<br />
using stl thread (boost also avaliable)<br />
<h2>update 8/2/2021: </h2>
<dl>
<dt>Added features</dt>
<dd>General memory saftey improved. I have being doing crypto-analysis on this implementation, and found a few areas of improvements; including random number generation upgrades, stack allocation improvements, and so on.</dd>
<dd>MacOs clang compatibility, testing to see if clang can be applied to other versions</dd>
<dt>Fixes</dt>
  <dd>Encryption on the same file yield 100% different results, or operation-to-operation random nonce is up-to standards</dd>
  <dd>Numerous memory fixes</dd>
</dl>
<h2>updated 7/7/2021: </h2>
<dl>
<dt>Added features</dt>
<dd>installation script ("src/update-bin.sh") for macos and linux</dd>
<dd>completely random nonce generation</dd>
<dd>sha3 enabled</dd>
<dd>new command line interface</dd>
<dt>Fixes</dt>
  <dd>no repeated nonce</dd>
  <dd>disk reading is mostly serialized</dd>
  <dd>disk writing is completely serialized</dd>
  <dd>minor memory fixes</dd>
</dl>
<br />
<h2>benchmark:</h2>
<dl>
<dt>for a 2 gb video file, reading and writing to disk </dt>
<dd>20 round chacha20: ~5.1sec </dd>
<dd>12 round chacha20: ~3.10sec </dd>
  <dl>
<h2>usage:</h2>
<p>
goto src folder<br />
run shall script "sh build_t"<br />
<dl>
<li>flag "-h": hide the status bar</li>
<li>flag "-s": disable sha3 hash output</li>

<li>encrypted files have ORIGINAL_FILE.pdm pattern</li>
<li>decrypted files have dec-ORIGINAL_FILE pattern</li>
<li>input only ORIGINAL_FILE</li>

</dl>
</p>

