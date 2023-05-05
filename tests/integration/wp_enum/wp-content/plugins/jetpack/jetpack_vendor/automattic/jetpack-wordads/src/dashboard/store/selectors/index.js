import noticeSelectors from 'components/global-notices/store/selectors';
import featureSelectors from './feature';
import jetpackSettingSelectors from './jetpack-settings';
import siteDataSelectors from './site-data';
import userDataSelectors from './user-data';

const selectors = {
	...siteDataSelectors,
	...jetpackSettingSelectors,
	...userDataSelectors,
	...noticeSelectors,
	...featureSelectors,
};

export default selectors;
