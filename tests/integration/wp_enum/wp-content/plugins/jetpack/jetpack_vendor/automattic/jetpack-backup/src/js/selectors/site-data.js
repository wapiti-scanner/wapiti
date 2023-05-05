const siteDataSelectors = {
	getSiteData: state => state.siteData || [],
	getSiteTitle: state => state.siteData?.title || '',
};

export default siteDataSelectors;
