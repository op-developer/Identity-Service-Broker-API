// TODO: Use the latest commit date
date = new Date().toISOString().split('T')[0];
exports.header = {
  height: "1cm",
  contents: function(pageNum, numPages) {
    return "<div style='float:right'>" + date + " &nbsp; " + pageNum + " / " + numPages + "</div>"
  }
}

exports.footer = null
