// (function () {
//   $('#revealSecret').click(function () {
//     var form = $('<form/>')
//       .attr('id', 'revealSecretForm')
//       .attr('method', 'post');
//     form.appendTo($('body'));
//     form.submit();
//   });
// })();

(function () {
  $('#sendRevealerMessage').change( function() {
    if($(this).is(':checked')) {
      $('#revealerMessage').show('slow');
    } else {
      $('#revealerMessage').hide('slow');
    }
  })
})();