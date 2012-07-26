description = [[
]]

---
-- @usage
-- nmap --script http-exif-spider -p80 <host>
--
--
-- @output
--

author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive"}

local shortport = require 'shortport'
local http = require 'http'
local stdnse = require 'stdnse'
local httpspider = require 'httpspider'
local string = require 'string'
local nsedebug = require 'nsedebug'
local bin = require 'bin'

TAG_INTEROP_INDEX          = 0x0001
TAG_INTEROP_VERSION        = 0x0002
TAG_IMAGE_WIDTH            = 0x0100
TAG_IMAGE_LENGTH           = 0x0101
TAG_BITS_PER_SAMPLE        = 0x0102
TAG_COMPRESSION            = 0x0103
TAG_PHOTOMETRIC_INTERP     = 0x0106
TAG_FILL_ORDER             = 0x010A
TAG_DOCUMENT_NAME          = 0x010D
TAG_IMAGE_DESCRIPTION      = 0x010E
TAG_MAKE                   = 0x010F
TAG_MODEL                  = 0x0110
TAG_SRIP_OFFSET            = 0x0111
TAG_ORIENTATION            = 0x0112
TAG_SAMPLES_PER_PIXEL      = 0x0115
TAG_ROWS_PER_STRIP         = 0x0116
TAG_STRIP_BYTE_COUNTS      = 0x0117
TAG_X_RESOLUTION           = 0x011A
TAG_Y_RESOLUTION           = 0x011B
TAG_PLANAR_CONFIGURATION   = 0x011C
TAG_RESOLUTION_UNIT        = 0x0128
TAG_TRANSFER_FUNCTION      = 0x012D
TAG_SOFTWARE               = 0x0131
TAG_DATETIME               = 0x0132
TAG_ARTIST                 = 0x013B
TAG_WHITE_POINT            = 0x013E
TAG_PRIMARY_CHROMATICITIES = 0x013F
TAG_TRANSFER_RANGE         = 0x0156
TAG_JPEG_PROC              = 0x0200
TAG_THUMBNAIL_OFFSET       = 0x0201
TAG_THUMBNAIL_LENGTH       = 0x0202
TAG_Y_CB_CR_COEFFICIENTS   = 0x0211
TAG_Y_CB_CR_SUB_SAMPLING   = 0x0212
TAG_Y_CB_CR_POSITIONING    = 0x0213
TAG_REFERENCE_BLACK_WHITE  = 0x0214
TAG_RELATED_IMAGE_WIDTH    = 0x1001
TAG_RELATED_IMAGE_LENGTH   = 0x1002
TAG_CFA_REPEAT_PATTERN_DIM = 0x828D
TAG_CFA_PATTERN1           = 0x828E
TAG_BATTERY_LEVEL          = 0x828F
TAG_COPYRIGHT              = 0x8298
TAG_EXPOSURETIME           = 0x829A
TAG_FNUMBER                = 0x829D
TAG_IPTC_NAA               = 0x83BB
TAG_EXIF_OFFSET            = 0x8769
TAG_INTER_COLOR_PROFILE    = 0x8773
TAG_EXPOSURE_PROGRAM       = 0x8822
TAG_SPECTRAL_SENSITIVITY   = 0x8824
TAG_GPSINFO                = 0x8825
TAG_ISO_EQUIVALENT         = 0x8827
TAG_OECF                   = 0x8828
TAG_EXIF_VERSION           = 0x9000
TAG_DATETIME_ORIGINAL      = 0x9003
TAG_DATETIME_DIGITIZED     = 0x9004
TAG_COMPONENTS_CONFIG      = 0x9101
TAG_CPRS_BITS_PER_PIXEL    = 0x9102
TAG_SHUTTERSPEED           = 0x9201
TAG_APERTURE               = 0x9202
TAG_BRIGHTNESS_VALUE       = 0x9203
TAG_EXPOSURE_BIAS          = 0x9204
TAG_MAXAPERTURE            = 0x9205
TAG_SUBJECT_DISTANCE       = 0x9206
TAG_METERING_MODE          = 0x9207
TAG_LIGHT_SOURCE           = 0x9208
TAG_FLASH                  = 0x9209
TAG_FOCALLENGTH            = 0x920A
TAG_SUBJECTAREA            = 0x9214
TAG_MAKER_NOTE             = 0x927C
TAG_USERCOMMENT            = 0x9286
TAG_SUBSEC_TIME            = 0x9290
TAG_SUBSEC_TIME_ORIG       = 0x9291
TAG_SUBSEC_TIME_DIG        = 0x9292
TAG_WINXP_TITLE            = 0x9c9b
TAG_WINXP_COMMENT          = 0x9c9c
TAG_WINXP_AUTHOR           = 0x9c9d
TAG_WINXP_KEYWORDS         = 0x9c9e
TAG_WINXP_SUBJECT          = 0x9c9f
TAG_FLASH_PIX_VERSION      = 0xA000
TAG_COLOR_SPACE            = 0xA001
TAG_PIXEL_X_DIMENSION      = 0xA002
TAG_PIXEL_Y_DIMENSION      = 0xA003
TAG_RELATED_AUDIO_FILE     = 0xA004
TAG_INTEROP_OFFSET         = 0xA005
TAG_FLASH_ENERGY           = 0xA20B
TAG_SPATIAL_FREQ_RESP      = 0xA20C
TAG_FOCAL_PLANE_XRES       = 0xA20E
TAG_FOCAL_PLANE_YRES       = 0xA20F
TAG_FOCAL_PLANE_UNITS      = 0xA210
TAG_SUBJECT_LOCATION       = 0xA214
TAG_EXPOSURE_INDEX         = 0xA215
TAG_SENSING_METHOD         = 0xA217
TAG_FILE_SOURCE            = 0xA300
TAG_SCENE_TYPE             = 0xA301
TAG_CFA_PATTERN            = 0xA302
TAG_CUSTOM_RENDERED        = 0xA401
TAG_EXPOSURE_MODE          = 0xA402
TAG_WHITEBALANCE           = 0xA403
TAG_DIGITALZOOMRATIO       = 0xA404
TAG_FOCALLENGTH_35MM       = 0xA405
TAG_SCENE_CAPTURE_TYPE     = 0xA406
TAG_GAIN_CONTROL           = 0xA407
TAG_CONTRAST               = 0xA408
TAG_SATURATION             = 0xA409
TAG_SHARPNESS              = 0xA40A
TAG_DISTANCE_RANGE         = 0xA40C
TAG_IMAGE_UNIQUE_ID        = 0xA420

TagTable = {}
TagTable[TAG_INTEROP_INDEX]         = "InteropIndex"
TagTable[TAG_INTEROP_VERSION]       = "InteropVersion"
TagTable[TAG_IMAGE_WIDTH]           = "ImageWidth"
TagTable[TAG_IMAGE_LENGTH]          = "ImageLength"
TagTable[TAG_BITS_PER_SAMPLE]       = "BitsPerSample"
TagTable[TAG_COMPRESSION]           = "Compression"
TagTable[TAG_PHOTOMETRIC_INTERP]    = "PhotometricInterpretation"
TagTable[TAG_FILL_ORDER]            = "FillOrder"
TagTable[TAG_DOCUMENT_NAME]         = "DocumentName"
TagTable[TAG_IMAGE_DESCRIPTION]     = "ImageDescription"
TagTable[TAG_MAKE]                  = "Make"
TagTable[TAG_MODEL]                 = "Model"
TagTable[TAG_SRIP_OFFSET]           = "StripOffsets"
TagTable[TAG_ORIENTATION]           = "Orientation"
TagTable[TAG_SAMPLES_PER_PIXEL]     = "SamplesPerPixel"
TagTable[TAG_ROWS_PER_STRIP]        = "RowsPerStrip"
TagTable[TAG_STRIP_BYTE_COUNTS]     = "StripByteCounts"
TagTable[TAG_X_RESOLUTION]          = "XResolution"
TagTable[TAG_Y_RESOLUTION]          = "YResolution"
TagTable[TAG_PLANAR_CONFIGURATION]  = "PlanarConfiguration"
TagTable[TAG_RESOLUTION_UNIT]       = "ResolutionUnit"
TagTable[TAG_TRANSFER_FUNCTION]     = "TransferFunction"
TagTable[TAG_SOFTWARE]              = "Software"
TagTable[TAG_DATETIME]              = "DateTime"
TagTable[TAG_ARTIST]                = "Artist"
TagTable[TAG_WHITE_POINT]           = "WhitePoint"
TagTable[TAG_PRIMARY_CHROMATICITIES]= "PrimaryChromaticities"
TagTable[TAG_TRANSFER_RANGE]        = "TransferRange"
TagTable[TAG_JPEG_PROC]             = "JPEGProc"
TagTable[TAG_THUMBNAIL_OFFSET]      = "ThumbnailOffset"
TagTable[TAG_THUMBNAIL_LENGTH]      = "ThumbnailLength"
TagTable[TAG_Y_CB_CR_COEFFICIENTS]  = "YCbCrCoefficients"
TagTable[TAG_Y_CB_CR_SUB_SAMPLING]  = "YCbCrSubSampling"
TagTable[TAG_Y_CB_CR_POSITIONING]   = "YCbCrPositioning"
TagTable[TAG_REFERENCE_BLACK_WHITE] = "ReferenceBlackWhite"
TagTable[TAG_RELATED_IMAGE_WIDTH]   = "RelatedImageWidth"
TagTable[TAG_RELATED_IMAGE_LENGTH]  = "RelatedImageLength"
TagTable[TAG_CFA_REPEAT_PATTERN_DIM]= "CFARepeatPatternDim"
TagTable[TAG_CFA_PATTERN1]          = "CFAPattern"
TagTable[TAG_BATTERY_LEVEL]         = "BatteryLevel"
TagTable[TAG_COPYRIGHT]             = "Copyright"
TagTable[TAG_EXPOSURETIME]          = "ExposureTime"
TagTable[TAG_FNUMBER]               = "FNumber"
TagTable[TAG_IPTC_NAA]              = "IPTC/NAA"
TagTable[TAG_EXIF_OFFSET]           = "ExifOffset"
TagTable[TAG_INTER_COLOR_PROFILE]   = "InterColorProfile"
TagTable[TAG_EXPOSURE_PROGRAM]      = "ExposureProgram"
TagTable[TAG_SPECTRAL_SENSITIVITY]  = "SpectralSensitivity"
TagTable[TAG_GPSINFO]               = "GPS Dir offset"
TagTable[TAG_ISO_EQUIVALENT]        = "ISOSpeedRatings"
TagTable[TAG_OECF]                  = "OECF"
TagTable[TAG_EXIF_VERSION]          = "ExifVersion"
TagTable[TAG_DATETIME_ORIGINAL]     = "DateTimeOriginal"
TagTable[TAG_DATETIME_DIGITIZED]    = "DateTimeDigitized"
TagTable[TAG_COMPONENTS_CONFIG]     = "ComponentsConfiguration"
TagTable[TAG_CPRS_BITS_PER_PIXEL]   = "CompressedBitsPerPixel"
TagTable[TAG_SHUTTERSPEED]          = "ShutterSpeedValue"
TagTable[TAG_APERTURE]              = "ApertureValue"
TagTable[TAG_BRIGHTNESS_VALUE]      = "BrightnessValue"
TagTable[TAG_EXPOSURE_BIAS]         = "ExposureBiasValue"
TagTable[TAG_MAXAPERTURE]           = "MaxApertureValue"
TagTable[TAG_SUBJECT_DISTANCE]      = "SubjectDistance"
TagTable[TAG_METERING_MODE]         = "MeteringMode"
TagTable[TAG_LIGHT_SOURCE]          = "LightSource"
TagTable[TAG_FLASH]                 = "Flash"
TagTable[TAG_FOCALLENGTH]           = "FocalLength"
TagTable[TAG_MAKER_NOTE]            = "MakerNote"
TagTable[TAG_USERCOMMENT]           = "UserComment"
TagTable[TAG_SUBSEC_TIME]           = "SubSecTime"
TagTable[TAG_SUBSEC_TIME_ORIG]      = "SubSecTimeOriginal"
TagTable[TAG_SUBSEC_TIME_DIG]       = "SubSecTimeDigitized"
TagTable[TAG_WINXP_TITLE]           = "Windows-XP Title"
TagTable[TAG_WINXP_COMMENT]         = "Windows-XP comment"
TagTable[TAG_WINXP_AUTHOR]          = "Windows-XP author"
TagTable[TAG_WINXP_KEYWORDS]        = "Windows-XP keywords"
TagTable[TAG_WINXP_SUBJECT]         = "Windows-XP subject"
TagTable[TAG_FLASH_PIX_VERSION]     = "FlashPixVersion"
TagTable[TAG_COLOR_SPACE]           = "ColorSpace"
TagTable[TAG_PIXEL_X_DIMENSION]     = "ExifImageWidth"
TagTable[TAG_PIXEL_Y_DIMENSION]     = "ExifImageLength"
TagTable[TAG_RELATED_AUDIO_FILE]    = "RelatedAudioFile"
TagTable[TAG_INTEROP_OFFSET]        = "InteroperabilityOffset"
TagTable[TAG_FLASH_ENERGY]          = "FlashEnergy"
TagTable[TAG_SPATIAL_FREQ_RESP]     = "SpatialFrequencyResponse"
TagTable[TAG_FOCAL_PLANE_XRES]      = "FocalPlaneXResolution"
TagTable[TAG_FOCAL_PLANE_YRES]      = "FocalPlaneYResolution"
TagTable[TAG_FOCAL_PLANE_UNITS]     = "FocalPlaneResolutionUnit"
TagTable[TAG_SUBJECT_LOCATION]      = "SubjectLocation"
TagTable[TAG_EXPOSURE_INDEX]        = "ExposureIndex"
TagTable[TAG_SENSING_METHOD]        = "SensingMethod"
TagTable[TAG_FILE_SOURCE]           = "FileSource"
TagTable[TAG_SCENE_TYPE]            = "SceneType"
TagTable[TAG_CFA_PATTERN]           = "CFA Pattern"
TagTable[TAG_CUSTOM_RENDERED]       = "CustomRendered"
TagTable[TAG_EXPOSURE_MODE]         = "ExposureMode"
TagTable[TAG_WHITEBALANCE]          = "WhiteBalance"
TagTable[TAG_DIGITALZOOMRATIO]      = "DigitalZoomRatio"
TagTable[TAG_FOCALLENGTH_35MM]      = "FocalLengthIn35mmFilm"
TagTable[TAG_SUBJECTAREA]           = "SubjectArea"
TagTable[TAG_SCENE_CAPTURE_TYPE]    = "SceneCaptureType"
TagTable[TAG_GAIN_CONTROL]          = "GainControl"
TagTable[TAG_CONTRAST]              = "Contrast"
TagTable[TAG_SATURATION]            = "Saturation"
TagTable[TAG_SHARPNESS]             = "Sharpness"
TagTable[TAG_DISTANCE_RANGE]        = "SubjectDistanceRange"
TagTable[TAG_IMAGE_UNIQUE_ID]       = "ImageUniqueId"

GPS_TAG_VERSIONID        = 0X00
GPS_TAG_LATITUDEREF      = 0X01
GPS_TAG_LATITUDE         = 0X02
GPS_TAG_LONGITUDEREF     = 0X03
GPS_TAG_LONGITUDE        = 0X04
GPS_TAG_ALTITUDEREF      = 0X05
GPS_TAG_ALTITUDE         = 0X06
GPS_TAG_TIMESTAMP        = 0X07
GPS_TAG_SATELLITES       = 0X08
GPS_TAG_STATUS           = 0X09
GPS_TAG_MEASUREMODE      = 0X0A
GPS_TAG_DOP              = 0X0B
GPS_TAG_SPEEDREF         = 0X0C
GPS_TAG_SPEED            = 0X0D
GPS_TAG_TRACKREF         = 0X0E
GPS_TAG_TRACK            = 0X0F
GPS_TAG_IMGDIRECTIONREF  = 0X10
GPS_TAG_IMGDIRECTION     = 0X11
GPS_TAG_MAPDATUM         = 0X12
GPS_TAG_DESTLATITUDEREF  = 0X13
GPS_TAG_DESTLATITUDE     = 0X14
GPS_TAG_DESTLONGITUDEREF = 0X15
GPS_TAG_DESTLONGITUDE    = 0X16
GPS_TAG_DESTBEARINGREF   = 0X17
GPS_TAG_DESTBEARING      = 0X18
GPS_TAG_DESTDISTANCEREF  = 0X19
GPS_TAG_DESTDISTANCE     = 0X1A
GPS_TAG_PROCESSINGMETHOD = 0X1B
GPS_TAG_AREAINFORMATION  = 0X1C
GPS_TAG_DATESTAMP        = 0X1D
GPS_TAG_DIFFERENTIAL     = 0X1E

GpsTagTable = {}
GpsTagTable[GPS_TAG_VERSIONID]       = "VersionID"
GpsTagTable[GPS_TAG_LATITUDEREF]     = "LatitudeRef"
GpsTagTable[GPS_TAG_LATITUDE]        = "Latitude"
GpsTagTable[GPS_TAG_LONGITUDEREF]    = "LongitudeRef"
GpsTagTable[GPS_TAG_LONGITUDE]       = "Longitude"
GpsTagTable[GPS_TAG_ALTITUDEREF]     = "AltitudeRef"
GpsTagTable[GPS_TAG_ALTITUDE]        = "Altitude"
GpsTagTable[GPS_TAG_TIMESTAMP]       = "Timestamp"
GpsTagTable[GPS_TAG_SATELLITES]      = "Satellites"
GpsTagTable[GPS_TAG_STATUS]          = "Status"
GpsTagTable[GPS_TAG_MEASUREMODE]     = "MeasureMode"
GpsTagTable[GPS_TAG_DOP]             = "Dop"
GpsTagTable[GPS_TAG_SPEEDREF]        = "SpeedRef"
GpsTagTable[GPS_TAG_SPEED]           = "Speed"
GpsTagTable[GPS_TAG_TRACKREF]        = "TrafRef"
GpsTagTable[GPS_TAG_TRACK]           = "Track"
GpsTagTable[GPS_TAG_IMGDIRECTIONREF] = "ImgDirectionRef"
GpsTagTable[GPS_TAG_IMGDIRECTION]    = "ImgDirection"
GpsTagTable[GPS_TAG_MAPDATUM]        = "MapDatum"
GpsTagTable[GPS_TAG_DESTLATITUDEREF] = "DestLatitudeRef"
GpsTagTable[GPS_TAG_DESTLATITUDE]    = "DestLatitude"
GpsTagTable[GPS_TAG_DESTLONGITUDEREF]= "DestLongitudeRef"
GpsTagTable[GPS_TAG_DESTLONGITUDE]   = "DestLongitude"
GpsTagTable[GPS_TAG_DESTBEARINGREF]  = "DestBearingref"
GpsTagTable[GPS_TAG_DESTBEARING]     = "DestBearing"
GpsTagTable[GPS_TAG_DESTDISTANCEREF] = "DestDistanceRef"
GpsTagTable[GPS_TAG_DESTDISTANCE]    = "DestDistance"
GpsTagTable[GPS_TAG_PROCESSINGMETHOD]= "ProcessingMethod"
GpsTagTable[GPS_TAG_AREAINFORMATION] = "AreaInformation"
GpsTagTable[GPS_TAG_DATESTAMP]       = "Datestamp"
GpsTagTable[GPS_TAG_DIFFERENTIAL]    = "Differential"

FMT_BYTE      =  1
FMT_STRING    =  2
FMT_USHORT    =  3
FMT_ULONG     =  4
FMT_URATIONAL =  5
FMT_SBYTE     =  6
FMT_UNDEFINED =  7
FMT_SSHORT    =  8
FMT_SLONG     =  9
FMT_SRATIONAL = 10
FMT_SINGLE    = 11
FMT_DOUBLE    = 12

bytes_per_format = {0,1,1,2,4,8,1,1,2,4,8,4,8}

portrule = shortport.http

function decode_value(endian, format, data, pos)
  local value, value2
  if(format == FMT_SBYTE or format == FMT_BYTE) then
    pos, value = bin.unpack(endian .. "C", data, pos)
    return pos, value
  elseif(format == FMT_USHORT) then
    pos, value = bin.unpack(endian .. "S", data, pos)
    return pos, value
  elseif(format == FMT_ULONG or format == FMT_SLONG) then
    pos, value = bin.unpack(endian .. "I", data, pos)
    return pos, value
  elseif(format == FMT_SSHORT) then
    pos, value = bin.unpack(endian .. "S", data, pos)
    return pos, value
  elseif(format == FMT_URATIONAL or format == FMT_SRATIONAL) then
    pos, value, value2 = bin.unpack(endian .. "II", data, pos)
    return pos, value / value2
  elseif(format == FMT_SINGLE or format == FMT_DOUBLE) then
    -- TODO
    stdnse.print_debug(1, "Not supported!")
    os.exit()
  end
end

function process_gps(data, pos, endian)
  local value, offset

  local pos, num_entries = bin.unpack(endian .. "S", data, pos)
  local latitude, longitude

  for i=1, num_entries do
    pos, tag, format, components = bin.unpack(endian .. "SSI", data, pos)
    local GpsTag = GpsTagTable[tag]

    local component_size = bytes_per_format[format + 1]
    local byte_count = components * component_size

    if(byte_count > 4) then
      pos, value  = bin.unpack(endian .. "I", data, pos)
    else
      pos, value = bin.unpack(endian .. "I", data, pos)
    end

    if(tag == GPS_TAG_LATITUDE or tag == GPS_TAG_LONGITUDE) then
      local dummy_pos, p1, p2, p3, p1_top, p1_bottom, p2_top, p2_bottom, p3_top, p3_bottom
      dummy_pos, p1 = decode_value(endian, format, data, value + 8)
      dummy_pos, p2 = decode_value(endian, format, data, dummy_pos)
      dummy_pos, p3 = decode_value(endian, format, data, dummy_pos)

      if(tag == GPS_TAG_LATITUDE) then
        latitude = (string.format("%0.0fd %0.0fm %0.3fs", p1, p2, p3))
      else
        longitude = (string.format("%0.0fd %0.0fm %0.3fs", p1, p2, p3))
      end
    end
  end

  return latitude, longitude
end

function parse_exif(s)
  local pos, sig, marker, size, exif_data
  local tag, format, components, byte_count, value, offset, dummy, data
  local latitude, longitude

  -- Parse the jpeg header, make sure it's valid
  pos, sig = bin.unpack(">S", s, pos)
  if(sig ~= 0xFFD8) then
    return false, "Unexpected signature"
  end

  -- Parse the sections
  while(true) do
    pos, marker, size = bin.unpack(">SS", s, pos)

    -- Check if we found the exif metadata section
    if(marker == 0xffe1) then
      break
    elseif(not(marker)) then
      return false, "Could not found EXIF marker"
    end

    pos = pos + size - 2 -- -2 for the marker size
  end

  pos, exif_data = bin.unpack(string.format(">A%d", size), s, pos)

  local pos, header1, header2, endian = bin.unpack(">ISS", exif_data, 1)
  if(header1 ~= 0x45786966 or header2 ~= 0x0000) then
    return false, "Invalid EXIF header"
  end

  if(endian == 0x4d4d) then
    endian = ">"
  elseif(endian == 0x4949) then
    endian = "<"
  else
    return false, "Unrecognized endianness"
  end

  local pos, tiff_header_1, first_offset = bin.unpack(endian .. "SI", exif_data, pos)
  if(tiff_header_1 ~= 0x002A or first_offset ~= 0x00000008) then
    return false, "Invalid tiff header"
  end

  pos = first_offset + 8 - 1 -- -1 because of lua's 1-based indexing

  -- Start processing a directory
  local pos, num_entries = bin.unpack(endian .. "S", exif_data, pos)

  for i=1,num_entries do
    pos, tag, format, components = bin.unpack(endian .. "SSI", exif_data, pos)
    byte_count = components * bytes_per_format[format + 1]

    if(byte_count <= 4) then
      pos, value = bin.unpack(endian .. "I", exif_data, pos)
    else
      pos, value = bin.unpack(endian .. "I", exif_data, pos)
    end

    -- We mostly care about GPS_INFO
    if(tag == TAG_GPSINFO) then
      latitude, longitude = process_gps(exif_data, value + 8 - 1, endian)
    end
  end

  return true, latitude, longitude
end

function action(host, port)
  f = io.open("/home/ron/topleft.jpg", "r")
  a = f:read("*all")

  local pattern = "%.jpg"
  local images = {}

  -- once we know the pattern we'll be searching for, we can set up the function
  check_response = function(body) return string.find(body, pattern) end

  -- create a new crawler instance
	local crawler = httpspider.Crawler:new(	host, port, nil, { scriptname = SCRIPT_NAME, noblacklist = true} )

	if ( not(crawler) ) then
		return
	end

	local return_table = {}

	while(true) do
	  local status, r = crawler:crawl()

	  if ( not(status) ) then
		  if ( r.err ) then
			  return stdnse.format_output(true, ("ERROR: %s"):format(r.reason))
		  else
			  break
		  end
	  end

	  -- first we try rfi on forms
	  if r.response and r.response.body and r.response.status==200 and string.match(r.url.path, ".jpg") then
      local status, latitude, longitude = parse_exif(r.response.body)

      if(1 == 1) then
        images[#images + 1] = string.format("%s contains embedded GPS: %s, %s", r.url.path, latitude, longitude)
      end
	  end --if
  end

--  return nsedebug.tostr(images)
  if(#images > 0) then
    return stdnse.format_output(true, images)
  end
end

