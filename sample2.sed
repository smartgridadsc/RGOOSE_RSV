<?xml version="1.0"?>
<SCL xmlns:sxy="http://www.iec.ch/61850/2003/SCLcoordinates" xmlns="http://www.iec.ch/61850/2003/SCL">
	<Header id="SS-SS S1 – S2" toolID="SSI-Tool" nameStructure="IEDName"/>


	<Substation name = "S1" desc="substation">
	</Substation>
	<Substation name = "S2" desc="substation">
	</Substation>


	<Substation name = "LineL2" desc="Line between S1 and S2">
		<VoltageLevel name="H1" desc="Line Voltage Level">
			<Bay name="L2" desc="Bay" sxy:x="55" sxy:y="62" sxy:dir="vertical">
				<ConductingEquipment name="LL2" desc="Overhead line" type="LIN" sxy:x="2" sxy:y="12">
					<Terminal name="S1H1B4N1" connectivityNode="S1/D1/B4/N1" substationName="S1" voltageLevelName="H1" bayName="B4" cNodeName="N1" />
					<Terminal name="S2H1B1N1" connectivityNode="S2/H1/B1/N1" substationName="S2" voltageLevelName="H1" bayName="B1" cNodeName="N1" />
				</ConductingEquipment>
			</Bay>
		</VoltageLevel>
	</Substation>


	<Communication>
		<SubNetwork name="S1net" desc="IEC61850 through both stations" type="8-MMS">

			<ConnectedAP iedName="S1_IED22" apName="S1">
				<Address>
					<P type="SA">0</P>
					<P type="IP">192.169.1.2</P>
					<P type="IP-SUBNET">255.255.0.0</P>
					<P type="OSI-AP-Title">1,3,9999,23</P>
					<P type="OSI-AE-Qualifier">23</P>
					<P type="OSI-TSEL">0001</P>
					<P type="OSI-PSEL">00000001</P>
					<P type="OSI-SSEL">0001</P>
				</Address>
				<SMV cbName="L2Diff22-R-SV" desc="R-SV from S1_IED22" ldInst="LD1">
					<Address>
						<P type="IP">238.0.0.2</P>
						<P type="APPID">0001</P>
						<P type="VLAN-ID">0</P>
						<P type="VLAN-PRIORITY">4</P>
					</Address>
				</SMV>
				<SMV cbName="L2Diff23-R-SV" desc="R-SV from S1_IED23" ldInst="LD1">
					<Address>
						<P type="IP">238.0.0.3</P>
						<P type="APPID">0003</P>
						<P type="VLAN-ID">0</P>
						<P type="VLAN-PRIORITY">4</P>
					</Address>
				</SMV>
				<SMV cbName="L2Diff24-R-SV" desc="R-SV from S1_IED24" ldInst="LD1">
					<Address>
						<P type="IP">238.0.0.4</P>
						<P type="APPID">0004</P>
						<P type="VLAN-ID">0</P>
						<P type="VLAN-PRIORITY">4</P>
					</Address>
				</SMV>
				<GSE ldInst="LD1" cbName="CB22_Status-R-GOOSE">
					<Address>
						<P type="IP">238.0.1.1</P>
						<P type="APPID">0005</P>
						<P type="VLAN-ID">0</P>
						<P type="VLAN-PRIORITY">4</P>
					</Address>
					<MinTime multiplier="m" unit="s">1000</MinTime>
					<MaxTime multiplier="m" unit="s">60000</MaxTime>
				</GSE>
				<GSE ldInst="LD1" cbName="CB33_Status-R-GOOSE">
					<Address>
						<P type="IP">238.0.1.2</P>
						<P type="APPID">0006</P>
						<P type="VLAN-ID">0</P>
						<P type="VLAN-PRIORITY">4</P>
					</Address>
					<MinTime multiplier="m" unit="s">1000</MinTime>
					<MaxTime multiplier="m" unit="s">60000</MaxTime>
				</GSE>
			</ConnectedAP>
		</SubNetwork>

		<SubNetwork name="S2net" desc="IEC61850 through both stations" type="8-MMS">

			<ConnectedAP iedName="S2_IED0" apName="S2">
				<Address>
					<P type="SA">0</P>
					<P type="IP">192.168.1.11</P>
					<P type="IP-SUBNET">255.255.0.0</P>
					<P type="OSI-AP-Title">1,3,9999,23</P>
					<P type="OSI-AE-Qualifier">23</P>
					<P type="OSI-TSEL">0001</P>
					<P type="OSI-PSEL">00000001</P>
					<P type="OSI-SSEL">0001</P>
				</Address>
				<SMV cbName="L2Diff0-R-SV" desc="R-SV from S2_IED0" ldInst="LD1">
					<Address>
						<P type="IP">238.0.0.1</P>
						<P type="APPID">0002</P>
						<P type="VLAN-ID">0</P>
						<P type="VLAN-PRIORITY">4</P>
					</Address>
				</SMV>
			</ConnectedAP>
			
		</SubNetwork>
	</Communication>


	<IED name="S1_IED22" type="" manufacturer="">
		<Services>
			<DynAssociation />
			<GetDirectory />
			<GetDataObjectDefinition />
			<DataObjectDirectory />
			<GetDataSetValue />
			<DataSetDirectory />
			<ConfDataSet max="10" maxAttributes="100" modify="true" />
			<ReadWrite />
			<ConfReportControl max="10" bufConf="false" />
			<GetCBValues />
			<SMVSettings cbName="L2Diff22-R-SV" datSet="measurementsofIED22toS2" appID="0001" dataLabel="measurementsofIED22toS2" />
			<SMVSettings cbName="L2Diff23-R-SV" datSet="measurementsofIED23toS2" appID="0003" dataLabel="measurementsofIED23toS2" />
			<SMVSettings cbName="L2Diff24-R-SV" datSet="measurementsofIED24toS2" appID="0004" dataLabel="measurementsofIED24toS2" />
			<GSESettings cbName="CB22_Status-R-GOOSE" datSet="StatusofCB22" appID="0005" dataLabel="Status info of CB22" />
			<GSESettings cbName="CB33_Status-R-GOOSE" datSet="StatusofCB33" appID="0006" dataLabel="Status info of CB33" />
			<GOOSE max="10" fixedOffs="false" />
		</Services>
		<AccessPoint name="S1">
			<LDevice inst="LD1">
				<LN0 lnClass="LLN0" inst="1" lnType="LD1.LLN0">
					<DataSet name="measurementsofIED22toS2">
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="A.phsA" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="A.phsB" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="A.phsC" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="PhV.phsA" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="PhV.phsB" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="PhV.phsC" daName="cVal" fc="MX" />
					</DataSet>
					<DataSet name="StatusofCB22">
						<FCDA IdInst="LD1" lnInst="0" lnClass="XCBR" doName="Pos" daName="DPC" fc="MX" />
					</DataSet>
					<DataSet name="StatusofCB33">
						<FCDA IdInst="LD1" lnInst="0" lnClass="XCBR" doName="Pos" daName="DPC" fc="MX" />
					</DataSet>
					<SampledValueControl Name="L2Diff22-R-SV" desc="R-SV from S1_IED22" datSet="measurementsofIED22toS2">
						<IEDName>S2_IED0</IEDName>
					</SampledValueControl>
					<SampledValueControl Name="L2Diff23-R-SV" desc="R-SV from S1_IED23" datSet="measurementsofIED23toS2">
						<IEDName>S2_IED0</IEDName>
					</SampledValueControl>
					<SampledValueControl Name="L2Diff24-R-SV" desc="R-SV from S1_IED24" datSet="measurementsofIED24toS2">
						<IEDName>S2_IED0</IEDName>
					</SampledValueControl>
					<GSEControl Name="CB22_Status-R-GOOSE" desc="Status info of CB22" type="GOOSE" fixedOffs="false" confRev="0" appID="0005" datSet="StatusofCB22">
						<IEDName>S2_IED0</IEDName>
					</GSEControl >
					<GSEControl Name="CB33_Status-R-GOOSE" desc="Status info of CB33" type="GOOSE" fixedOffs="false" confRev="0" appID="0006" datSet="StatusofCB33">
						<IEDName>S2_IED0</IEDName>
					</GSEControl >
				</LN0>
				<LN lnClass="MMXU" inst="0" lnType="LD1.MMXU0" />
				<LNode lnClass="XCBR" inst="0" lnType="LD1.XCBR" />
			</LDevice>
		</AccessPoint>
	</IED>

	<IED name="S2_IED0" type="" manufacturer="">
		<Services>
			<DynAssociation />
			<GetDirectory />
			<GetDataObjectDefinition />
			<DataObjectDirectory />
			<GetDataSetValue />
			<DataSetDirectory />
			<ConfDataSet max="10" maxAttributes="100" modify="true" />
			<ReadWrite />
			<ConfReportControl max="10" bufConf="false" />
			<GetCBValues />
			<SMVSettings cbName="L2Diff0-R-SV" datSet="measurementsofIED0toS1" appID="0002" dataLabel="measurementsofIED0toS1" />
		</Services>
		<AccessPoint name="S2">
			<LDevice inst="LD1">
				<LN0 lnClass="LLN0" inst="1" lnType="LD1.LLN0">
					<DataSet name="measurementsofIED0toS1">
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="A.phsA" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="A.phsB" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="A.phsC" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="PhV.phsA" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="PhV.phsB" daName="cVal" fc="MX" />
						<FCDA ldInst="LD1" lnInst="0" lnClass="MMXU" doName="PhV.phsC" daName="cVal" fc="MX" />
					</DataSet>
					<SampledValueControl Name="L2Diff0-R-SV" desc="R-SV from S2_IED0" datSet="measurementsofIED0toS1">
						<IEDName>S1_IED22</IEDName>
					</SampledValueControl>
				</LN0>
				<LN lnClass="MMXU" inst="0" lnType="LD1.MMXU1" />
			</LDevice>
		</AccessPoint>
	</IED>

	<DataTypeTemplates>
		<LNodeType id="LD1.LLN0" lnClass="LLN0">
			<DO name="NamPlt" type="LPL" />
			<DO name="Beh" type="ENS" />
			<DO name="Mod" type="ENC" />
		</LNodeType>
		<LNodeType id="LD1.XCBR" lnClass="XCBR">
			<DO name="Beh" type="ENS" />
			<DO name="Health" type="ENS" />
			<DO name="Loc" type="SPS" />
			<DO name="Mod" type="ENC" />
			<DO name="OpCnt" type="INS" />
			<DO name="Pos" type="DPC" />
			<DO name="BlkOpn" type="SPC" />
			<DO name="BlkCls" type="SPC" />
		</LNodeType>
		<LNodeType id="LD1.MMXU0" lnClass="MMXU">
			<DO name="TotW" type="MV" />
			<DO name="Beh" type="ENS" />
			<DO name="TotVAr" type="MV" />
			<DO name="TotVA" type="MV" />
			<DO name="PPV" type="DEL" />
			<DO name="PhV" type="WYE" />
			<DO name="A" type="WYE" />
		</LNodeType>
		<LNodeType id="LD1.MMXU1" lnClass="MMXU">
			<DO name="TotW" type="MV" />
			<DO name="Beh" type="ENS" />
			<DO name="TotVAr" type="MV" />
			<DO name="TotVA" type="MV" />
			<DO name="PPV" type="DEL" />
			<DO name="PhV" type="WYE" />
			<DO name="A" type="WYE" />
		</LNodeType>
	</DataTypeTemplates>
</SCL>
