const noticeSelectors = {
	getNotices: state => state.notices.notices ?? [],
};

export default noticeSelectors;
