<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="bsrsetup_options">
    <!-- ignore -->
  </xsl:template>

  <xsl:template match="pick_bsrsetup_option">
    <xsl:variable name="name" select="@name"/>
    <varlistentry>
      <xsl:apply-templates select="//bsrsetup_options/bsrsetup_option[@name=$name]/term"/>
      <listitem>
	<xsl:apply-templates select="//bsrsetup_options/bsrsetup_option[@name=$name]/definition/*"/>
      </listitem>
    </varlistentry>
  </xsl:template>

  <xsl:template match="bsrsetup_option//indexterm">
    <!-- ignore -->
  </xsl:template>

  <xsl:template match="bsrsetup_option//only-bsrsetup">
    <xsl:copy-of select="node()"/>
  </xsl:template>

  <xsl:template match="bsrsetup_option//only-bsr-conf">
    <!-- ignore -->
  </xsl:template>

  <xsl:template match="bsrsetup_option/term/option">
    <xsl:variable name="args" select="@*"/>
    <option>
      <xsl:text>--</xsl:text>
      <xsl:copy-of select="node()"/>
    </option>
  </xsl:template>
</xsl:stylesheet>
