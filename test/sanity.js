var expect    = require("chai").expect;

describe("Sanity Check", function() {
  describe("First check", function() {
    it("Simple addition", function() {
      expect(1+1).to.equal(2)
    });
  });
  
  describe("Second check", function() {
    it("Simple multiplication", function() {
      expect(5*9).to.equal(45)
    });
  });
});