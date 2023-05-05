const APISelectors = {
	getAPIRoot: state => state.API.WP_API_root || null,
	getAPINonce: state => state.API.WP_API_nonce || null,
	getRegistrationNonce: state => state.API.registrationNonce || null,
};

export default APISelectors;
