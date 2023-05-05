/* globals wp, lodash */
window.videoPressUploadPoster = function ( guid, data ) {
	// eslint-disable-next-line no-undef
	return new Promise( function ( resolve, reject ) {
		wp.media.ajax( 'videopress-get-upload-token', { async: true } ).done( function ( response ) {
			// Set auth header with upload token.
			var headers = {},
				options = {};
			var body = new FormData();
			headers[ 'Authorization' ] =
				'X_UPLOAD_TOKEN token="' +
				response.upload_token +
				'" blog_id="' +
				response.upload_blog_id +
				'"';
			options.headers = headers;
			options.method = 'POST';
			options.url = 'https://public-api.wordpress.com/rest/v1.1/videos/' + guid + '/poster';

			// Handle CORS.
			options.credentials = 'omit';

			Object.keys( data ).forEach( key => {
				body.append( key, data[ key ] );
			} );

			options.body = body;

			wp.apiFetch( options )
				.then( function ( res ) {
					resolve( res );
				} )
				.catch( function ( error ) {
					reject( error );
				} );
		} );
	} );
};

window.videoPressGetPoster = function ( guid ) {
	const getPosterRequest = ( resolve, reject, jwt = null ) => {
		let url = 'https://public-api.wordpress.com/rest/v1.1/videos/' + guid + '/poster';
		if ( jwt && jwt.length ) {
			url += '?metadata_token=' + jwt;
		}

		wp.apiFetch( {
			url: url,
			method: 'GET',
			credentials: 'omit',
		} )
			.then( function ( res ) {
				resolve( res );
			} )
			.catch( function ( error ) {
				reject( error );
			} );
	};

	return new Promise( function ( resolve, reject ) {
		wp.ajax
			.post( 'videopress-get-playback-jwt', {
				async: true,
				guid: guid,
			} )
			.done( function ( response ) {
				getPosterRequest( resolve, reject, response.jwt );
			} )
			.fail( () => {
				// Also try on ajax failure if the video doesn't need a jwt anyway
				getPosterRequest( resolve, reject );
			} );
	} );
};

window.videoPressUploadTrack = function ( guid, kind, srcLang, label, vttFile ) {
	// eslint-disable-next-line no-undef
	return new Promise( function ( resolve, reject ) {
		wp.media
			.ajax( 'videopress-get-upload-token', { async: true, data: { filename: vttFile.name } } ) // todo: maybe remove filename from here (not needed)
			.done( function ( response ) {
				// Set auth header with upload token.
				var headers = {},
					options = {};
				var body = new FormData();
				headers[ 'Authorization' ] =
					'X_UPLOAD_TOKEN token="' +
					response.upload_token +
					'" blog_id="' +
					response.upload_blog_id +
					'"';
				options.headers = headers;
				options.method = 'POST';
				options.url = 'https://public-api.wordpress.com/rest/v1.1/videos/' + guid + '/tracks';

				// Handle CORS.
				options.credentials = 'omit';

				body.append( 'kind', kind );
				body.append( 'srclang', srcLang );
				body.append( 'label', label );
				body.append( 'vtt', vttFile );

				options.body = body;

				wp.apiFetch( options )
					.then( function ( res ) {
						resolve( res );
					} )
					.catch( function ( error ) {
						reject( error );
					} );
			} );
	} );
};

window.videoPressDeleteTrack = function ( guid, kind, srcLang ) {
	// eslint-disable-next-line no-undef
	return new Promise( function ( resolve, reject ) {
		wp.media.ajax( 'videopress-get-upload-token', { async: true } ).done( function ( response ) {
			// Set auth header with upload token.
			var headers = {},
				options = {};
			var body = new FormData();
			headers[ 'Authorization' ] =
				'X_UPLOAD_TOKEN token="' +
				response.upload_token +
				'" blog_id="' +
				response.upload_blog_id +
				'"';
			options.headers = headers;
			options.method = 'POST';
			options.url = 'https://public-api.wordpress.com/rest/v1.1/videos/' + guid + '/tracks/delete';

			// Handle CORS.
			options.credentials = 'omit';

			body.append( 'kind', kind );
			body.append( 'srclang', srcLang );
			options.body = body;

			wp.apiFetch( options )
				.then( function ( res ) {
					resolve( res );
				} )
				.catch( function ( error ) {
					reject( error );
				} );
		} );
	} );
};

wp.apiFetch.use( function ( options, next ) {
	var path = options.path;
	var method = options.method;
	var body = options.body;

	// Override only requests to the WP REST API media endpoint uploading new videos.
	if ( ! path || path.indexOf( '/wp/v2/media' ) === -1 ) {
		return next( options );
	}
	if ( ! method || 'post' !== method.toLowerCase() ) {
		return next( options );
	}
	var file = body ? body.get( 'file' ) : null;
	if ( ! file || file.type.indexOf( 'video/' ) !== 0 ) {
		return next( options );
	}

	// Get upload token.
	wp.media
		.ajax( 'videopress-get-upload-token', { async: false, data: { filename: file.name } } )
		.done( function ( response ) {
			// Set auth header with upload token.
			var headers = options.headers || {};
			headers.Authorization =
				'X_UPLOAD_TOKEN token="' +
				response.upload_token +
				'" blog_id="' +
				response.upload_blog_id +
				'"';
			options.headers = headers;

			// Replace upload URL.
			delete options.path;
			options.url = response.upload_action_url;

			// Handle CORS.
			options.credentials = 'omit';

			// Set data in expected param by WP.com media endpoint.
			body.set( 'media[]', file );
			body.delete( 'file' );
			options.body = body;
		} );

	var result = next( options );

	return new Promise( function ( resolve, reject ) {
		result
			.then( function ( response ) {
				if ( response instanceof Response && response.ok ) {
					return response.json();
				}

				return response; // if not a response object, then its our parsed body so return that
			} )
			.then( function ( data ) {
				var wpcomMediaObject = lodash.get( data, 'media[0]' );
				var id = lodash.get( wpcomMediaObject, 'ID' );
				var gutenbergMediaObject = wp.apiFetch( {
					path: '/wp/v2/media/' + id,
				} );
				resolve( gutenbergMediaObject );
			} )
			.catch( function ( error ) {
				if ( 'errors' in error && 'object' === typeof error.errors && error.errors.length > 0 ) {
					error = error.errors.shift();
				}
				reject( error );
			} );
	} );
} );
