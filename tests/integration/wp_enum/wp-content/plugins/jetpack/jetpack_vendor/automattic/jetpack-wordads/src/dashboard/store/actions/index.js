import noticeActions from 'components/global-notices/store/actions';
import siteSettingActions from './jetpack-settings';

const actions = {
	...siteSettingActions,
	...noticeActions,
};

export default actions;
