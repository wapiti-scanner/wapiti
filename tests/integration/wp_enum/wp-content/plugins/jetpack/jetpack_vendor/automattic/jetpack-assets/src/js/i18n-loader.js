const i18n = require( '@wordpress/i18n' );
const { default: md5 } = require( 'md5-es' );

const locationMap = {
	plugin: 'plugins/',
	theme: 'themes/',
	core: '',
};

const hasOwn = ( obj, prop ) => Object.prototype.hasOwnProperty.call( obj, prop );

module.exports = {
	state: {
		baseUrl: null,
		locale: null,
		domainMap: {},
		domainPaths: {},
	},

	/**
	 * Download and register translations for a bundle.
	 *
	 * @param {string} path - Bundle path being fetched. May have a query part.
	 * @param {string} domain - Text domain to register into.
	 * @param {string} location - Location for the translation: 'plugin', 'theme', or 'core'.
	 * @returns {Promise} Resolved when the translations are registered, or rejected with an `Error`.
	 */
	async downloadI18n( path, domain, location ) {
		const state = this.state;
		if ( ! state || typeof state.baseUrl !== 'string' ) {
			throw new Error( 'wp.jpI18nLoader.state is not set' );
		}

		// "en_US" is the default, no translations are needed.
		if ( state.locale === 'en_US' ) {
			return;
		}

		// Check that fetch is available.
		if ( typeof fetch === 'undefined' ) {
			throw new Error( 'Fetch API is not available.' );
		}

		// Extract any query part and hash the script name like WordPress does.
		const pathPrefix = hasOwn( state.domainPaths, domain ) ? state.domainPaths[ domain ] : '';
		let hash, query;
		const i = path.indexOf( '?' );
		if ( i >= 0 ) {
			hash = md5.hash( pathPrefix + path.substring( 0, i ) );
			query = path.substring( i );
		} else {
			hash = md5.hash( pathPrefix + path );
			query = '';
		}

		// Download.
		const locationAndDomain = hasOwn( state.domainMap, domain )
			? state.domainMap[ domain ]
			: locationMap[ location ] + domain;
		const res = await fetch(
			// prettier-ignore
			`${ state.baseUrl }${ locationAndDomain }-${ state.locale }-${ hash }.json${ query }`
		);
		if ( ! res.ok ) {
			throw new Error( `HTTP request failed: ${ res.status } ${ res.statusText }` );
		}
		const data = await res.json();

		// Extract the messages from the file and register them.
		const localeData = hasOwn( data.locale_data, domain )
			? data.locale_data[ domain ]
			: data.locale_data.messages;
		localeData[ '' ].domain = domain;
		i18n.setLocaleData( localeData, domain );
	},
};
