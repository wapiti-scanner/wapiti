<?php include W3TC_INC_DIR . '/options/common/header.php'; ?>

<div id="wufoo-m5pom8z0qy59rm"></div>
<form>

<script type="text/javascript">var m5pom8z0qy59rm;(function(d, t) {
var s = d.createElement(t);
var options = {
	'userName':'w3edge',
	'formHash': w3tc_support_data.form_hash,
	'autoResize':true,
	'height':'1145',
	'async':true,
	'host':'wufoo.com',
	'header':'show',
	'defaultValues':
		'field221=' + encodeURI(w3tc_support_data.postprocess) +
		'&field6=' + encodeURI(w3tc_support_data.first_name) +
		'&field7=' + encodeURI(w3tc_support_data.last_name) +
		'&field8=' + encodeURI(w3tc_support_data.home_url) +
		'&field9=' + encodeURI(w3tc_support_data.email),
	'ssl':true
};

if (w3tc_support_data.field_name.length > 0)
	options.defaultValues += '&' +
		encodeURI(w3tc_support_data.field_name) + '=' +
		encodeURI(w3tc_support_data.field_value);


s.src = ('https:' == d.location.protocol ? 'https://' : 'http://') + 'www.wufoo.com/scripts/embed/form.js';
s.onload = s.onreadystatechange = function() {
var rs = this.readyState; if (rs) if (rs != 'complete') if (rs != 'loaded') return;
try { m5pom8z0qy59rm = new WufooForm();m5pom8z0qy59rm.initialize(options);m5pom8z0qy59rm.display(); } catch (e) {}};
var scr = d.getElementsByTagName(t)[0], par = scr.parentNode; par.insertBefore(s, scr);
})(document, 'script');</script>
