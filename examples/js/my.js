$(document).ready(function() {
    selectedForm = $('#id_form_link');
    $('#id_api_name').change(function() {
        var apiName = $('#id_api_name').val();
        console.log(apiName);
        selectedForm.hide();
        if (apiName === 'link_user') {
            selectedForm = $('#id_form_link');
        } else if (apiName === 'unlink_user') {
            selectedForm = $('#id_form_unlink');
        } else if (apiName === 'merge') {
            selectedForm = $('#id_form_merge');
        } else if (apiName === 'diassociate') {
            selectedForm = $('#id_form_disassociate');
        } else if (apiName === 'profile') {
            selectedForm = $('#id_form_profile');
        } else if (apiName === 'associate_token') {
            selectedForm = $('#id_form_associate');
        }
        selectedForm.show();
    });

    function updateResult(response) {
        var json = JSON.stringify(response, null, 2);
        $('#result').html(json);
        $('#result').each(function(i, element) {
            hljs.highlightBlock(element);
        });
    }

    function linkUser() {
        $.ajax({
            url: '/api/link',
            type: 'POST',
            dataType: 'json',
            data: {
                'user_id': $('#id_user_id_link').val(),
                'social_id': $('#id_social_id_link').val(),
                'response_type': 'json'
            }
        }).done(updateResult);
    }

    function unlinkUser() {
        $.ajax({
            url: '/api/unlink',
            type: 'POST',
            dataType: 'json',
            data: {
                'user_id': $('#id_user_id_unlink').val(),
                'social_id': $('#id_social_id_unlink').val(),
                'response_type': 'json'
            }
        }).done(updateResult);
    }

    function mergeProfiles() {
        $.ajax({
            url: '/api/merge',
            type: 'POST',
            dataType: 'json',
            data: {
                'src_user_id': $('#id_src_user_id_merge').val(),
                'src_social_id': $('#id_src_social_id_merge').val(),
                'dst_user_id': $('#id_dst_user_id_merge').val(),
                'dst_social_id': $('#id_dst_social_id_merge').val(),
                'response_type': 'json'
            }
        }).done(updateResult);
    }

    function diassociate() {
        $.ajax({
            url: '/api/disassociate',
            type: 'POST',
            dataType: 'json',
            data: {
                user_id: $('#id_user_id_disassociate').val(),
                social_id: $('#id_social_id_disassociate').val(),
                providers: $('#id_providers_disassociate').val()
            }
        }).done(updateResult);
    }

    function getProfile() {
        $.ajax({
            url: '/api/profile',
            type: 'POST',
            dataType: 'json',
            data: {
                user_id: $('#id_user_id_profile').val(),
                social_id: $('#id_social_id_profile').val()
            }
        }).done(updateResult);
    }

    function getAssociateToken() {
        $.ajax({
            url: '/api/associate_token',
            type: 'POST',
            dataType: 'json',
            data: {
                user_id: $('#id_user_id_associate').val(),
                social_id: $('#id_social_id_associate').val(),
                provider: $('#id_target_provider_associate').val()
            }
        }).done(updateResult);
    }

    $('#btn_submit').click(function() {
        var apiName = $('#id_api_name').val();
        console.log('Call API: ' + apiName);
        if (apiName === 'link_user') {
            linkUser();
        } else if (apiName === 'unlink_user') {
            unlinkUser();
        } else if (apiName === 'merge') {
            mergeProfiles();
        } else if (apiName === 'diassociate') {
            diassociate();
        } else if (apiName === 'profile') {
            getProfile();
        } else if (apiName === 'associate_token') {
            getAssociateToken();
        }
    });
});