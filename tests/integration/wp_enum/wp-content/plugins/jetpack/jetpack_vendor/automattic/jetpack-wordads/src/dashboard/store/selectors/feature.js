const featureSelectors = {
	isFeatureEnabled: ( state, feature ) => {
		return Array.isArray( state.features ) && state.features.includes( feature );
	},
};

export default featureSelectors;
