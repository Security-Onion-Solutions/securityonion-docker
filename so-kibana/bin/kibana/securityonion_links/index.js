export default function (kibana) {
  return new kibana.Plugin({
    require: ['elasticsearch'],
    name: 'securityonion_links',
    uiExports: {
	links: [
		{
			id: 'kibana:squert',
			title: 'Squert',
			order: 9998,
			url: '/squert',
			description: 'squert',
			icon: 'plugins/kibana/assets/play-circle.svg'
		},
		{
			id: 'kibana:logout',
			title: 'Logout',
			order: 9999,
			url: '/logout.html',
			description: 'logout',
			icon: 'plugins/kibana/assets/logout.svg'
		}]
    },

    config(Joi) {
      return Joi.object({
        enabled: Joi.boolean().default(true),
      }).default();
    },
  });
}
