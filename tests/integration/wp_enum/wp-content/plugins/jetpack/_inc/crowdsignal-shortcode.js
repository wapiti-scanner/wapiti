( function ( w, d, c, j ) {
	if (
		w.crowdsignal_shortcode_options &&
		w.crowdsignal_shortcode_options.script_url &&
		! d.getElementById( j )
	) {
		var pd = d.createElement( c ),
			s;
		pd.id = j;
		pd.async = true;
		pd.src = w.crowdsignal_shortcode_options.script_url;
		s = d.getElementsByTagName( c )[ 0 ];
		s.parentNode.insertBefore( pd, s );
	} else {
		// In environments where jQuery is present, dispatch with jQuery.
		if ( typeof w.jQuery !== 'undefined' ) {
			w.jQuery( d.body ).trigger( 'pd-script-load' );
		} else {
			d.body.dispatchEvent( new Event( 'pd-script-load' ) );
		}
	}
} )( window, document, 'script', 'pd-polldaddy-loader' );
