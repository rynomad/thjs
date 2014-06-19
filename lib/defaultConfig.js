module.exports = {
  chan_timeout : 10000,   // how long before for ending durable channels w/ no acks
  seek_timeout : 3000,    // shorter tolerance for seeks, is far more lossy
  chan_autoack : 1000,    // is how often we auto ack if the app isn't generating responses in a durable channel
  chan_resend : 2000,     // resend the last packet after this long if it wasn't acked in a durable channel
  chan_outbuf : 100,      // max size of outgoing buffer before applying backpressure
  chan_inbuf : 50,        // how many incoming packets to cache during processing/misses
  nat_timeout : 30*1000,  // nat timeout for inactivity
  idle_timeout : 2*defaults.nat_timeout,        // overall inactivity timeout
  link_timer : defaults.nat_timeout - (5*1000), // how often the DHT link maintenance runs
  link_max : 256,         // maximum number of links to maintain overall (minimum one packet per link timer)
  link_k : 8,             // maximum number of links to maintain per bucket
};
