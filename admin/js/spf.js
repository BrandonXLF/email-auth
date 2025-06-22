/* global eauthSpfApi */

jQuery(($) => {
	const checker = EmailAuthPlugin.instance.makeChecker(
		'spf',
		'SPF',
		() => `${eauthSpfApi.check}/${EmailAuthPlugin.instance.bounceDomain}`,
		() => {
			if (EmailAuthPlugin.instance.bounceDomain === null) {
				return {
					pass: null,
					reason: 'Unknown bounce address domain.',
				};
			}
		},
		(res) => {
			const out = [
				$('<div>').append(
					'Result code: ',
					$('<code>').text(res.code),
					' for server ',
					$('<code>').text(res.server_ip),
					' ',
					$('<button>')
						.attr('type', 'button')
						.text('Configure Server IP')
						.addClass('button-link')
						.on('click', () =>
							$('#eauth-spf-set-ip-dialog')[0].showModal()
						)
				),
				EmailAuthPlugin.createCommentList(
					res.code_reasons,
					'Details',
					'h4'
				),
			];

			out.push($('<h3>').text('Validity Check'));

			if (res.record) {
				out.push(
					$('<div>').append(
						'Current record: ',
						$('<code>').text(res.record)
					)
				);
			}

			if (res.validity === false) {
				out.push(
					$('<div>').append(
						`${EmailAuthPlugin.EMOJIS.error} No syntactically valid record found.`
					)
				);
			} else if (!res.validity.length) {
				out.push(
					$('<div>').append(
						`${EmailAuthPlugin.EMOJIS.pass} Current record is schematically valid.`
					)
				);
			} else {
				out.push(
					EmailAuthPlugin.createCommentList(
						res.validity,
						'Issues',
						'h4'
					)
				);
			}

			if (res.rec_dns) {
				out.push($('<h3>').text('Suggested DNS Record'));

				out.push(
					EmailAuthPlugin.createTxtRecord(
						EmailAuthPlugin.instance.bounceDomain,
						res.rec_dns
					),
					EmailAuthPlugin.createCommentList(
						res.rec_reasons,
						'Reasons',
						'h4'
					)
				);
			}

			return out;
		},
		{
			get: () => EmailAuthPlugin.instance.bounceDomain,
			type: 'Bounce Address',
			link: '#bounce-address',
		},
		{
			get: () => EmailAuthPlugin.instance.bounceDomain,
		}
	);

	checker.boundCheck();
	EmailAuthPlugin.instance.addEventListener(
		'bouncedomainchange',
		checker.boundCheck
	);

	$('#eauth-spf-set-ip').on('click', async (e) => {
		e.preventDefault();

		const mode = $('[name="eauth_spf_server_ip"]:checked').val().trim();
		const custom = $('[name="eauth_spf_server_ip_custom"]').val().trim();

		const res = await EmailAuthPlugin.request(
			`${eauthSpfApi.setIp}`,
			'POST',
			{
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ mode, custom }),
			}
		);

		if (!res.ok) {
			return;
		}

		const json = await res.json();

		const escapedMode = CSS.escape(json.mode);
		$('[name="eauth_spf_server_ip"][value="' + escapedMode + '"]').prop(
			'checked',
			true
		);

		$('[name="eauth_spf_server_ip_custom"]').val(json.custom || '');

		$('#eauth-spf-set-ip-dialog')[0].close();
		checker.boundCheck();
	});

	$('#eauth-spf-set-ip-close').on('click', (e) => {
		e.preventDefault();
		$('#eauth-spf-set-ip-dialog')[0].close();
	});
});
