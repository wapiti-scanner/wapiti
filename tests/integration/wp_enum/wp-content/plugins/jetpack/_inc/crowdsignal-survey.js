( function ( d, c, j ) {
	if ( ! d.getElementById( j ) ) {
		var pd = d.createElement( c ),
			s;
		pd.id = j;
		pd.src = 'https://polldaddy.com/survey.js';
		s = d.getElementsByTagName( c )[ 0 ];
		s.parentNode.insertBefore( pd, s );
	}
} )( document, 'script', 'pd-embed' );
