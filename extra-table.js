// Manipulate table
(function($) {
	wpLdapAuthRoleEquiv = {
		template : null,
		tr_height : 0,
		default_role : '',
		target : null,
		init : function() {
			$('.equivalent-table :text').blur(function() { wpLdapAuthRoleEquiv.text_change($(this)); });
			$('.equivalent-table select').change(function() { wpLdapAuthRoleEquiv.update_equiv(); });
			$(".equivalent-table [value='+']").click(function() { wpLdapAuthRoleEquiv.add($(this)); });
			$(".equivalent-table [value='-']").click(function() { wpLdapAuthRoleEquiv.del($(this)); });
			$('.equivalent-table :button').eq(2).click(function() { wpLdapAuthRoleEquiv.up($(this)); });
			$('.equivalent-table :button').eq(3).click(function() { wpLdapAuthRoleEquiv.down($(this)); });
			this.template = $('.equivalent-table tbody tr').clone(true);
			$('.equivalent-table tbody').empty();
			this.default_role = $('#default_role').val();
			this.target = $('#LDAP_authentication_role_equivalent_groups');
			var role_equiv_groups = $.trim(this.target.val()).split(';');
			for (equiv_index in role_equiv_groups) {
				var role_group = role_equiv_groups[equiv_index].split('=');
				if (role_group.length != 2)
					continue;
				var ldap_group = $.trim(role_group[0]);
				var corresponding_role = $.trim(role_group[1]);
				$('.equivalent-table tbody').append(this.template.clone(true));
				$('.equivalent-table :text').eq(equiv_index).val(ldap_group);
				$('.equivalent-table select').eq(equiv_index).val(corresponding_role);
			}
			if ($('.equivalent-table tbody tr').length == 0) {
				$('.equivalent-table tbody').append(this.template.clone(true));
				$('.equivalent-table select').val(this.default_role);
			}
			$('.equivalent-table tr').show();
			this.update_table();
			$('#equivalent_dialog').show();
			var width = $('.equivalent-table :text').width() + $('.equivalent-table select').width() + ($('.equivalent-table :button').width() + 50) * 4;
			this.tr_height = $('.equivalent-table tbody tr').height();
			var height = $('#equivalent_dialog').height() + 60;
			$('#equivalent_dialog').dialog({
				autoOpen: false,
				minWidth: width,
				width: width,
				minHeight: height,
				height: height,
				modal: true,
				/*buttons: { 'OK': function() { $(this).dialog('close'); } },*/
				close: function(event, ui) { wpLdapAuthRoleEquiv.update_equiv(); $('#LDAP_authentication_role_equivalent_groups').removeAttr('readonly'); }
			}).removeAttr('title');
			this.target.focus(function() {
				$(this).attr('readonly', 'readonly');
				$('#equivalent_dialog').dialog('open');
			});
		},
		update_table : function() {
			$(".equivalent-table :button").removeAttr('disabled');
			if ($('.equivalent-table tbody tr').length == 1) {
				$(".equivalent-table :button").attr('disabled', 'disabled');
				$(".equivalent-table [value='+']").removeAttr('disabled');
			}
			$('.equivalent-table tbody tr:first :button').eq(2).attr('disabled', 'disabled');
			$('.equivalent-table tbody tr:last :button').eq(3).attr('disabled', 'disabled');
			$('.equivalent-table tr').removeClass('odd-row');
			$('.equivalent-table tr:odd').addClass('odd-row');
			this.update_equiv();
		},
		add : function(target) {
			var tr = target.parents('tr');
			tr.after(this.template.clone(true));
			tr.next().find('select').val(this.default_role);
			$('.ui-dialog').height($('.ui-dialog').height() + this.tr_height);
			$('#equivalent_dialog').dialog('setData', 'minHeight', $('.ui-dialog').height());
			tr.next().fadeIn('normal', function() { wpLdapAuthRoleEquiv.update_table(); });
		},
		del : function(target) {
			target.parents('tr').fadeOut('normal', function() { wpLdapAuthRoleEquiv.del_after(target); });
		},
		del_after : function(target) {
			target.parents('tr').remove();
			$('.ui-dialog').height($('.ui-dialog').height() - this.tr_height);
			$('#equivalent_dialog').dialog('setData', 'minHeight', $('.ui-dialog').height());
			this.update_table();
		},
		up : function(target) {
			var own = target.parents('tr');
			var prev = own.prev();
			own.add(prev).fadeOut('normal', function() { wpLdapAuthRoleEquiv.down_after(prev, own); });
		},
		down : function(target) {
			var own = target.parents('tr');
			var next = own.next();
			own.add(next).fadeOut('normal', function() { wpLdapAuthRoleEquiv.down_after(own, next); });
		},
		down_after : function(self, target) {
			self.add(target).show();
			self.insertAfter(target);
			this.update_table();
		},
		text_change : function(target) {
			target.val($.trim(target.val().replace(/[;=]/g, '')));
			this.update_equiv();
		},
		update_equiv : function() {
			var role_equiv_groups = $(".equivalent-table tbody tr:has(:text[value!=''])").map(function() {
				return $(this).find(':text,select').map(function() {
					return $(this).val();
				}).get().join('=');
			}).get().join(';');
			this.target.val(role_equiv_groups);
		}
	}
}(jQuery));

jQuery(document).ready( function() { wpLdapAuthRoleEquiv.init(); } );
