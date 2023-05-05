<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div class="lightbox-content-padded">
	<h3><?php esc_html_e( 'Security Headers: Quick Reference', 'w3-total-cache' ); ?></h3>

	<fieldset>
		<legend><?php esc_html_e( 'Legend', 'w3-total-cache' ); ?></legend>

		<p>
			All of the directives that end with -src support similar values known as
			a source list. Multiple source list values can be space separated with the exception of
			'none' which should be the only value.
		</p>
	</fieldset>

	<table class="w3tcbc_qrf">
		<tr>
			<th>Source Value</th>
			<th>Example</th>
			<th>Description</th>
		</tr>
		<tr>
			<td><code>*</code></td>
			<td><code>img-src *</code></td>
			<td>Wildcard, allows any URL except data: blob: filesystem: schemes</td>
		</tr>
		<tr>
			<td><code>'none'</code></td>
			<td><code>object-src 'none'</code></td>
			<td>Prevents loading resources from any source</td>
		</tr>
		<tr>
			<td><code>'self'</code></td>
			<td><code>script-src 'self'</code></td>
			<td>Allows loading resources from the same origin (same scheme, host and port)</td>
		</tr>
		<tr>
			<td><code>data:</code></td>
			<td><code>img-src 'self' data:</code></td>
			<td>Allows loading resources via the data scheme (e.g. Base64 encoded images)</td>
		</tr>
		<tr>
			<td><code>domain.example.com</code></td>
			<td><code>img-src domain.example.com</code></td>
			<td>Allows loading resources from the specified domain name</td>
		</tr>
		<tr>
			<td><code>*.example.com</code></td>
			<td><code>img-src *.example.com</code></td>
			<td>Allows loading resources from any subdomain under example.com</td>
		</tr>
		<tr>
			<td><code>https://cdn.com</code></td>
			<td><code>img-src https://cdn.com</code></td>
			<td>Allows loading resources only over <acronym title="HyperText Transfer Protocol over SSL">HTTPS</acronym> matching the given domain</td>
		</tr>
		<tr>
			<td><code>https:</code></td>
			<td><code>img-src https:</code></td>
			<td>Allows loading resources only over <acronym title="HyperText Transfer Protocol over SSL">HTTPS</acronym> on any domain</td>
		</tr>
		<tr>
			<td><code>'unsafe-inline'</code></td>
			<td><code>script-src 'unsafe-inline'</code></td>
			<td>Allows use of inline source elements such as style attribute, onclick, or script tag bodies (depends on the context of the source it is applied to)</td>
		</tr>
		<tr>
			<td><code>'unsafe-eval'</code></td>
			<td><code>script-src 'unsafe-eval'</code></td>
			<td>Allows unsafe dynamic code evaluation such as Javascript eval()</td>
		</tr>
	</table>
</div>
