/* global google, _wp_google_translate_widget, module */
function googleTranslateElementInit() {
	var lang = 'en';
	var langParam;
	var langRegex = /[?&#]lang=([a-zA-Z\-_]+)/;
	if (
		typeof _wp_google_translate_widget === 'object' &&
		typeof _wp_google_translate_widget.lang === 'string'
	) {
		lang = _wp_google_translate_widget.lang;
	}
	langParam = window.location.href.match( langRegex );
	if ( langParam ) {
		window.location.href =
			window.location.href.replace( langRegex, '' ).replace( /#googtrans\([a-zA-Z\-_|]+\)/, '' ) +
			'#googtrans(' +
			lang +
			'|' +
			langParam[ 1 ] +
			')';
	}
	new google.translate.TranslateElement(
		{
			pageLanguage: lang,
			layout: _wp_google_translate_widget.layout,
			autoDisplay: false,
		},
		'google_translate_element'
	);
}
if ( module ) {
	module.exports = googleTranslateElementInit;
}
